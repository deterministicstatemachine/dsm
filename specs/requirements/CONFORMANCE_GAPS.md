# CONFORMANCE_GAPS

Derived artifact. Not a source of protocol truth; `specs/README.md` governs. The requirements are the canonical rows of `MASTER_REQUIREMENTS.md` §8. This file records how the backend stands against each of them, and what the backend does that no requirement asks for. It combines the independent comparisons listed in §1; those files are inputs, and this file is the result.

---

## 1 Basis

| Input | Value |
|---|---|
| Requirements | `MASTER_REQUIREMENTS.md` §8.1–§8.4, 878 canonical rows, with MR-STOR-0055 and MR-SOFI-0068 as rewritten on 2026-09-23 (§3.3) |
| Storage §14 lines added after the original pin | compared as rows `STOR-014/Lnnn` (§8.5) |
| Code | `main` at `28c19cfe` (#974). Later commits change only `specs/requirements/`. |
| Crates | `dsm`, `dsm_sdk`, `dsm_storage_node`, and `proto/dsm_app.proto` |
| Not classified | §8.5 Open items of `MASTER_REQUIREMENTS.md`. They are not requirements. |
| Deferred | dBTC (owner, 2026-09-23): MR-DBTC-0001–0135, MR-DSM-0198, MR-DSM-0221–0237 |

This document merges three independent comparisons, whose files were removed once merged:

| Comparison | Form | Used as |
|---|---|---|
| Claude Code | every row classified, each with code locus and named test | the base: every row starts from its classification |
| ChatGPT | 14 findings, cited below as CG-01–CG-14, with requirement mappings and a section coverage ledger | corrections and additional findings (§3) |
| Gemini | every row classified | not used as evidence (§3.4) |

## 2 Method

**Step 1: Locate.** For each requirement, find the code that implements it (crate, file, function) and the test that exercises it. If nothing implements it, the row says so. No row is blank.

**Step 2: Classify.** Each requirement gets exactly one status:

| Status | Meaning |
|---|---|
| Met | Code implements it, and a named test fails if it is broken. |
| Partial | Code exists but no such test, or the code covers only part of the requirement. |
| Missing | No code. |
| Violated | Code does the opposite. |
| Not code | A specification or process rule with nothing to implement (theorems, fault-model assumptions, proof obligations, dependency boundaries). |
| Deferred | dBTC, out of this round. |

Rules applied in classifying:

1. **A test must be named and must fail when the requirement breaks.** "No test found", an absence argument, or a test that checks something nearby is Partial.
2. **A test that skips is not a test.** Six storage-node tests return early unless `DSM_RUN_DB_TESTS=1`; they pass on the board without running (§6.4). Since 2026-09-24 none skips: they are rewritten on the Postgres test store or deleted with the mechanism they tested.
3. **A SQLite-only test does not cover Postgres code.** `immutable_store_round_trip.rs`, `paidk_gating.rs` and `identity_milestone_e2e.rs` compile only under `local-dev`. Where the requirement's mechanism is SQL in `db/pg.rs`, the row is Partial. Since 2026-09-24 the SQLite backend is deleted and these suites run on Postgres.
4. **Code with no production caller is not the implementation.** The `State` transition layer (`core/state_machine/transition.rs`, `relationship.rs`, `bilateral.rs`) was reached only by its own tests, `core/state_machine/mod.rs` tests and `tools/vertical_validation`; it is deleted (§6.10). Rows first located there are located on the production path instead: `DeviceState::advance` and `dsm_sdk::sdk::receipts::verify_receipt_bytes`.
5. **SoFi reachability.** SoFi has no production entry (§4 G1). A row whose obligation has to happen in the running system (a producer, a relay, a write, a transition) and whose only implementation is unreachable is Partial. A prohibition, derivation, encoding or predicate property is classified on the library code and its tests. **On those rows, Met means implemented and tested, not live.**

Two independent passes produced the rows: a first pass per range, then a verification pass that re-read the code and demanded a named test. The reviewer then applied rules 1–5 across all ranges. The working tree was checked unchanged (`git status --porcelain`) before and after each fan-out.

## 3 Reconciliation

### 3.1 Rules

1. A row keeps the base classification unless a finding from another comparison is confirmed against the code and the requirement text.
2. A finding that contradicts a base "Met" is checked by reading the cited code and the requirement row. If confirmed, the row takes the finding's status and the note records where it came from.
3. A finding that is a different reading of the same code, and does not change what the requirement demands, adds a note but does not change the status.
4. A conflict between the code and the specification that is a design question, not a defect, goes to the owner. The owner's decision is recorded (§3.3).

### 3.2 Status changes

| MR-ID | Base | Reconciled |
|---|---|---|
| MR-SOFI-0030 | Met | Violated |
| MR-DSM-0030 | Violated | Partial |
| MR-STOR-0030 | Met | Violated |
| MR-STOR-0109 | Met | Violated |

Where the ChatGPT findings map to rows the base already classified the same way, the rows keep their status and the finding is cited in the note: CG-01 (G2), CG-03 (MR-DSM-0041, 0042, MR-STOR-0045), CG-04 (MR-SOFI-0248, 0252, 0329; MR-STOR-0050–0054), CG-06 (G5), CG-07 (MR-STOR-0082), CG-08 (MR-DSM-0062, 0202; MR-STOR-0102–0107, 0113), CG-11 (MR-STOR-0024, 0115–0118), CG-12 (MR-STOR-0087–0091) and CG-14, which the base records under MR-STOR-0006 and 0007 (G4).

### 3.3 Owner decision

**Storage-set identity (ChatGPT CG-05; MR-STOR-0055, MR-SOFI-0068).** The specifications said `storage_set_id` covers member ids only. The code commits each member's id paired with its register incarnation (CCB storage-set schema 3), so a member rebuilt under the same id is not the committed member. Owner, 2026-09-23: the specifications follow the code (SoFi Amendment S6, storage §10), to be revisited once members run enrolled appliances. Both rows were rewritten in `MASTER_REQUIREMENTS.md`; the finding is closed.

### 3.4 The Gemini comparison

It classifies every row, but its evidence does not survive checking, so none of its classifications is used:

- 136 of its Met rows cite `tests/core_tests.rs`; others cite `tests/state_machine_tests.rs`, `tests/bilateral_tests.rs`, `tests/economic_tests.rs` and `dsm_storage_node/tests/objects.rs`. None of these files exists.
- 248 SoFi rows are Met on a whole test module (`sofi/validation.rs:tests`) rather than a named test, and 68 rows cite `tests/common/mod.rs`, a helper.
- It classifies unbuilt mechanisms as Met, including route-chain finality (MR-DSM-0036), the candidate and guard state model (MR-DSM-0009, 0010, 0138) and a verifier-resolved registry (MR-STOR-0087).

Its 20 rows harsher than the base were read as leads. Three hold, all also found by ChatGPT: MR-SOFI-0030, MR-STOR-0030 and MR-STOR-0109. Four (MR-SOFI-0029, 0097, 0204, 0272) behave as their text requires and depend on the MR-SOFI-0030 fix; they keep Met with a note. The rest attach an unrelated general reason (writer authentication, missing seats) to rows about key custody, leader computation or liveness, or name nothing that contradicts the requirement.

## 4 Headline gaps

These are the gaps that account for most of the non-Met rows. Row lists are not exhaustive; §8 is.

**G1. SoFi has no production entry.** No handler, proto message or JNI export reaches the SoFi producers (`dsm_sdk/src/sdk/sofi_*.rs`) or the route pipeline (`sofi::validation::validate`, `sofi::conformance`, `sofi::resolution`, `sofi::exercise`, `sofi::registration`, `sofi::publication`). Live code reaches `sofi::signature::verify_operation` (from `DeviceState::advance`) and the helper modules `sofi::arith`, `sofi::fisher_yates`, `sofi::storage`, `sofi::lineage`, `sofi::wire` and `sofi::derive` (from the economic modules, the native reserve and `storage_io`). Rows: MR-SOFI-0001, 0013, 0017, 0020, 0023, 0031, 0033, 0037, 0048, 0144, 0165, 0255, 0256, 0257, 0258, 0259; MR-DSM-0187, 0209, 0211, 0212, 0214.

**G2. Route-chain finality is not implemented.** DSM Amendment A6, SoFi Amendment S4 and storage §9, §12.6, §14 and §23.1 item 7 make finality a route chain: the leader's link and two further links. `sofi::arith::resolve` still decides `LeaderHeld`/`Final` by "first at the leader, held by two other members", and it is live: the native reserve, economic registers, and the SoFi register, advance and exercise paths call it. The §14 arrival records and ByteCommits exist, but nothing consumes them. There is no route-entry type, no link, no `Preserved` state and no per-seat empties. Rows: MR-DSM-0034, 0036 (Violated), 0039, 0058, 0083, 0085 (Violated), 0208, 0270; MR-SOFI-0081, 0082, 0328; MR-STOR-0020, 0046, 0047, 0108, 0130–0134, 0136–0138; STOR-014/L415.

**G3. The candidate and guard state model is absent.** `DeviceState` has one flat root. There is no ρcore, P, Γ, Σ, Π, Ω, no committed position u, no guard families and no κres derivation. Rows Missing: MR-DSM-0009, 0010, 0025, 0120, 0123, 0124, 0127, 0129–0132, 0137–0139, 0143, 0144, 0146, 0148, 0149, 0151, 0155, 0159, 0201. Partial because of it: MR-DSM-0002, 0005, 0014, 0092, 0098, 0122, 0125, 0126, 0140, 0141, 0145, 0147, 0152–0154, 0156, 0157, 0160–0164, 0166, 0168, 0170, 0174, 0186, 0188, 0240, 0241, 0251, 0253, 0268.

**G4. The node's legacy object store does what the storage spec forbids.** It is mounted beside the conformant immutable store (`main.rs` merges both routers). It overwrites (`db/pg.rs::upsert_object`, `ON CONFLICT DO UPDATE`), deletes (`api/objects/store.rs::delete_object_proto`; `admin.rs::cleanup_expired_handler` → `cleanup_expired_objects_and_spool`), decodes payloads (`identity/authenticate.rs::authenticate_vaultpost_smart_policy_if_present`), refuses on capacity (`upsert_object_with_capacity_check`), checks the writer (`device_auth` on the object store and on `b0x/submit`), keys PaidK on the connected writer instead of the addressed account, and computes object placement and replication (`replication.rs`). The b0x handler branches on the decoded `Invoke.method` (`is_cert_resync_recovery`). Rows Violated: MR-STOR-0006, 0007, 0010, 0014, 0024, 0034, 0041, 0100, 0110, 0116, 0118, 0119; MR-DSM-0060, 0065, 0072, 0075.

**G5. Storage Part III is absent, and the registry is decided by the node.** There are no seats, occupants, succession, retirement or rebind records, no handover, no loss or pre-loss resolution, no challenges or drop claims, no storage credits and no opt-out. `registry/scaling.rs::trigger_registry_update` counts signals, ranks applicants and writes the winner into a mutable table the node owns. Rows Missing: MR-STOR-0015, 0019, 0050–0054, 0058–0062, 0064–0074, 0076–0081, 0083–0085, 0094, 0095, 0102–0107, 0113, 0114, 0128, 0139; MR-DSM-0059. Violated: MR-STOR-0087, 0088. Partial: MR-STOR-0089, 0090, 0092.

**G6. Withdrawn (owner review, 2026-09-23).** The base reported that Transfer, Mint and Burn advance a device root without a register write. They do not: the register write is in the SDK, not in Core's `DeviceState::advance`, which is where the base looked. `wallet.send` runs `process_online_transfer_logic`, which builds an economic admission, and `economic_admission_flow::finish_admission` calls `register_economic_root`; `token.burn` goes through `admitted_self_loop_operation`, the same admission (so does `token.mint`, which G7 removes). Every value-moving advance claims the next economic position at its cell, and the leader takes one value per position, so a forked device cannot place a second advance at a position already taken. MR-DSM-0030 is Partial, not Violated: implemented on every path, with no test that fails if the send path stopped registering.

**G7. Token supply is minted after genesis, which the spec forbids.** The spec fixes every token's supply in its policy at genesis, with no unlimited option (MR-SOFI-0306). For a native token, genesis supply equals unreleased units plus every balance plus burned units at every state; there is no minting after genesis, and emission is a release under the token's policy (MR-SOFI-0307). An externally backed token is issued only against a proven lock, once per lock (MR-SOFI-0308, 0309, 0319, 0320). The code inverts this: `token.create` makes unlimited supply the only creatable class and refuses capped supply (`CAPPED_TOKEN_ISSUANCE_UNSUPPORTED_IN_BETA`), `economic/issuance.rs::check_issuance_permitted` refuses `FiniteSupplyCap`, creation forces `initial_alloc = 0`, and supply arrives through `token.mint`, a discretionary operation the policy's signers can repeat. Separately, `check_market_leg_permitted` has no callers, so the transferable flag is not checked on transfers, vault creation or SoFi legs (MR-SOFI-0311).

The fix:
1. Remove `token.mint` and its handler, SDK path and frontend action.
2. `token.create` commits the full supply at genesis: the whole amount exists from the first state, held unreleased under the policy's emission rule or allocated at creation.
3. New native units come only from a release of unreleased units, never new units, and the conservation equation of MR-SOFI-0307 is checked at every state. For ERA in beta the release rule is the faucet (owner, 2026-09-23): `FaucetClaim` already releases from the native reserve (`NativeReserveRelease`) through the economic admission and does not mint. The release rule is a named rule of the token's policy, so an emission schedule can replace the faucet later without changing the release path. Emissions are out of beta.
4. Remove the unlimited class; the supply class is native or externally backed, fixed in the policy.
5. Call the transferable check on every transfer, vault creation and SoFi leg.

Rows: MR-SOFI-0306, 0307 (Violated), 0308, 0309, 0311, 0319–0321, 0323–0325.

**G8. SoFi wire and resolution defects.**
- `CLOSURE_FORBIDDEN_CONTENT_CLASSES` omits `SOFI_SETTLEMENT_SWAP`, `SOFI_SETTLEMENT_CLOSE`, `SOFI_TRADER_CORE`, `SOFI_DLV_CORE` and `SOFI_SETTLEMENT_PREIMAGE`. Its test iterates the same incomplete list, so it cannot catch the omission (MR-SOFI-0176, Violated).
- `resolution::route_impossible` never reads `RouteFacts.conformance`. A conformance-Invalid fulfillment whose final cell sits on the walked key is never skippable, so the attempt chain stalls (MR-SOFI-0238, Violated).
- Four of the six declared bounds (`MAX_VALIDATION_FETCH_BYTES`, `MAX_CLOSURE_OBJECT_BYTES`, `MAX_AUTH_ENVELOPES`, `MAX_PROVENANCE_FANOUT`) are never enforced (MR-SOFI-0163, 0180).
- The policy-fulfillment aux candidate mechanism is absent (MR-SOFI-0158–0162).
- `validate` never evaluates SetupRegistered or SetupValid; `Evidence` has no setup field (MR-SOFI-0136, 0205). ClaimRef at p is deferred on the `SofiSetup` arm (MR-SOFI-0135).
- The Core state machine names SoFi operations: `DeviceState::advance` matches on `SofiSetup`, `SofiVaultCreate` and `SofiFulfill` (MR-SOFI-0036, Violated).
- No challenge or drop-claim rung (ladder step 3a, Amendment S5) (MR-SOFI-0248, 0252, 0329).

**G9. The per-device SMT evicts relationship heads.** `SparseMerkleTree::update_leaf` evicts the oldest leaf once more than `max_leaves` are held, and the device SMT is created with `max_relationships = 1024` at genesis. `DeviceState::advance` takes its root and proofs from that tree (`smt_replace` → `update_leaf`). The `tips` map keeps every head, but the root does not commit to it. Past 1,024 relationships the oldest relationships drop out of the root, and transitions in them fail. A rewind does not get through, because the counterparty checks against its own tip. No beta device is expected to reach 1,024 relationships. Fix: a commitment tree never drops leaves; remove the eviction, as `economic/tree.rs` already does. Rows: MR-DSM-0116, 0121 (Violated).

**G10. The SDK records a negative verdict.** `recipient_staging::mark_rejected` persists a sticky `TerminalReject` with a reason and refuses to re-stage the pair. Row: MR-DSM-0018 (Violated).

**G11. The legacy DLV manager has no cross-receipt consumption registry.** `vault/dlv_manager.rs` documents that a double claim across stitched receipts is not enforced there. Its only production user is the Bitcoin tap SDK (`bitcoin_tap_sdk.rs`), which is dBTC and deferred, and it applies no token-balance effect directly (the direct path was removed because, without the registry, it allowed minting). SoFi vaults do not use it: each vault generation is consumed through its successor cell, one value per cell at the leader, which is the specification's single-consumption mechanism and becomes route-chain final with G2. The rows stay open because the general κres/Σ model they are stated over is absent (G3). Rows: MR-DSM-0142, 0152, 0164, 0166, 0168, 0170, 0174, 0176, 0188.

**G12. Core's predicates have a third value (ChatGPT CG-02). Settled: the fix is in the code, not the spec.** The rule is established (Amendment S3, MR-SOFI-0030): every Core predicate is binary over the evidence in hand. "Unavailable" is not a verdict. It is the network layer saying a fetch has not completed yet, and the answer to it is a retry, bounded and owned by the acquisition layer, never a value inside Core. The code still carries it inside Core: `sofi::conformance::Validation` is `Valid | Invalid | Unavailable`, its conjunction folds all three, and `FulfillmentConformance` and `route_validation` return it. The formal model does the same (`lean4/DSMSofiAtomicity.lean`, `Facts.conformance := .unavailable`).

Owner clarification, 2026-09-23: predicates have exactly two values, Valid and Invalid, and network status is separate. An operation fails on Invalid predicates; with Valid predicates it can still fail when its network retries are exhausted. There is no "not yet evaluated" state in the resolver's facts. In code the acquisition layer answers `Acquired::Exhausted`, and a SoFi position reports `RetriesExhausted`, distinct from `Invalid`.

The fix:
1. Core predicates become `Valid | Invalid` and are called only once acquisition has everything they need.
2. The acquisition layer (`acquire_evidence`, `acquire_conformance_evidence`, the cell reads) retries fetches up to its budget; if the budget runs out it returns "not yet" to its caller, outside Core, and nothing is evaluated or recorded.
3. The producer rule stays: a producer that cannot get complete evidence stops (MR-SOFI-0272).
4. The tests that assert `Unavailable` results from Core move to the acquisition layer, and the Lean `Facts` lose the third value.

Rows: MR-SOFI-0030 (Violated); dependent: MR-DSM-0017, MR-SOFI-0029, 0097, 0204, 0272.

**G13. SoFi resolution reads the network before it has checked what it already holds (ChatGPT CG-03). Settled: the fix is in the code.** The spec fixes the order (MR-DSM-0041, MR-DSM-0042, MR-STOR-0045): the receiver first runs every check it can decide from the presentation and its own state; if any is Invalid, the transition is Invalid and nothing is fetched. Only then does it read the register cell and fetch the rest.

`dsm_sdk::sdk::sofi_resolve::resolve_recognized` does it the other way round. After `recognize_exercise` (which binds the signatures and objects, and nothing more) it calls `read_registration`, a network read of the register cell, and only afterwards builds the in-hand closure, fetches conformance evidence, and runs `fulfillment_conformance` and `route_validation`. So an exercise that is signed and recognized but already fails a check decidable from its own bytes (for example, a fulfillment at a position that is not the successor) still causes register and evidence reads.

The fix:
1. Split `fulfillment_conformance` and `route_validation` into the part decidable from the exercise and the resolver's own state, and the part that needs fetched evidence.
2. Run the first part immediately after recognition. If it is Invalid, return Invalid with no I/O.
3. Then `read_registration`, then acquisition, then the second part.

Test: pass a correctly signed, recognized exercise with a non-successor fulfillment position through the real resolver with a storage spy; it must be Invalid with zero reads. Repeat for each check decidable in hand. The general receiver (`DeviceState::advance` with `verify_receipt_bytes`) should be traced for the same order; the base could not locate its ordering (MR-DSM-0041, 0042).

**G14. Replication before acknowledgement (ChatGPT CG-07). Closed by a spec amendment.** The storage spec still said an operator must replicate a role's memory before acknowledging a write. That predates route chains. Owner, 2026-09-23: the route chain is the replication. Each seat writes durably before it returns its arrival record, and a write counts only once its chain holds the leader's link and two further links, each committing the one before, so the three records qualify each other. No second copy behind a seat is required (storage §12.5 amended; MR-STOR-0082 rewritten). The code already writes durably before answering (`begin_durable_write`, `require_durable_commit_posture`); counting at three links is G2.

**G15. The finality tests and formal models prove the old rule (ChatGPT CG-13). In beta, together with G2.** Every artefact below encodes "Final = first at the leader and held by two other members". They are consistent with each other and prove the superseded rule, so they cannot certify route-chain finality. They are rewritten when G2 lands, not before, so that model, tests and code change together.

| Artefact | What it encodes |
|---|---|
| `dsm/src/sofi/arith.rs` tests (`the_leaders_first_value_held_by_two_others_is_final` and the five others) | Final from digest lists, no links, no arrival records |
| `dsm/tests/sofi_v8_independent.rs` (the `CellResolution::Final` / `LeaderHeld` cases) | Same rule, through the public API |
| `lean4/DSMSofiSuccessorCells.lean` (`copies`, `resolve`, `final_persists` and the lemmas under them) | The copy count and its persistence proof |
| `lean4/DSMSofiAtomicity.lean` (`Facts`, `resolve` over `cellsFinal…`) | Resolution over the old cell facts, with the three-valued conformance of G12 |
| `lean4/DSMNativeReserve.lean` | Release over the old finality |
| `tla/DSM_SofiSuccessorCells.tla` (`LeaderHeld`, `Final`, `copies` as counts, `ReadFinal`) | The copy rule as a model-checked state machine |
| `tla/DSM_SofiFulfillment.tla` and its `.cfg` variants | Fulfillment over the old finality |
| `tla/DSM_NativeReserveRelease.tla` and its `.cfg` variants (`CountWithoutLeader`, `AllMemberFinality`, `LossAtLeaderReachable`, …) | Release, loss and counting variants of the old rule |

The replacement:
1. **Model.** Each cell has a fixed route of five seats; each seat has an append-only log with arrival indexes and a running hash; a link is a seat's arrival record carrying the chain before it; empties are `taken` or `no_response`; each seat mirrors peers' ByteCommits only by fetching them itself.
2. **Invariants,** one per storage proof obligation (MR-STOR-0122–0127, 0143, 0144):
   - chain uniqueness: at most one value has a valid leader link, so at most one is Preserved or Final;
   - Final persists;
   - Preserved is never treated as spendable;
   - the loss rule decides from pre-loss chains only, and a chain first shown after the loss counts for nothing;
   - two valid chains are possible only if the leader equivocated, and then they freeze;
   - a mirror never holds a ByteCommit its member did not serve.
3. **Mutation configs** that must each produce a counterexample. The old bare-copy rule becomes a negative fixture: three copies with no chain must not be Final. The route-chain variants rejected during design each get their own config: a three-consecutive window, any ascending three, and the leader written last.
4. **Rust tests** mirroring the same cases against Core's chain evaluation, with the old positive fixture turned into a negative one.


**G16. Bilateral traffic is readable by the nodes (owner, 2026-09-23; in beta).** Nothing in the spool is encrypted: `message.send` posts its payload and memo in the clear to the relationship's inbox address, and transfer bodies, replies, evidence halves and checkpoints travel the same way. Each step's Kyber encapsulation only feeds the next per-step signing key. The specifications promise more: storage §8 says spool envelopes are never opened by the node and tip-mirror leaves are encrypted, and the DSM explainer says only the parties to a relationship hold its bytes. Fix (DSM Amendment A7, storage §8): each step's Kyber shared secret also yields a per-step message key under its own domain tag, and every spool payload is sealed under an authenticated cipher (XChaCha20-Poly1305 is already a dependency); a node holds ciphertext only. SoFi's objects and cells stay public by design. Also to check: whether tip-mirror leaves are stored encrypted, and what an ordinary transfer publishes to shared storage beyond the spool. Rows: MR-DSM-0070, 0271, 0272; MR-STOR-0034, 0145, 0146.

Resolved (owner, 2026-09-23): an inbox address is per relationship and changes every step, as the code already computes it (`B0xSDK::compute_b0x_address`: recipient genesis, recipient device id, relationship tip). The specifications were amended to match (DSM A3, storage §8, MR-STOR-0037); the code does not change.
## 5 Beta scope

Owner decisions of 2026-09-23 that bear on these rows:

- **Out of beta:** storage credits (MR-DSM-0062, 0202; MR-STOR-0102–0107, 0113), including nodes refusing writes to accounts whose credits are exhausted (MR-STOR-0147, settled 2026-09-23); seat retirement, handover and the loss path, and the rest of storage Part III except the registry (G5); the spend gate (MR-STOR-0100, 0109–0111, 0114), which is removed rather than fixed; DrainProofs, whose node-side endpoints #974 already removed.
- **In beta:** route-chain finality (G2, with G15); the legacy store and b0x violations (G4); taking the registry decision off the node (G5, MR-STOR-0087, 0088); the settled code fixes G12 (predicates binary, Unavailable is a network retry) and G13 (checks in hand before any read).
- **In beta (owner, 2026-09-23):** G7 (no minting after genesis; `token.mint` removed, supply fixed at creation, ERA released from the reserve by the faucet with the release rule replaceable by emissions later, token policy honoured on every transfer, vault creation and SoFi leg); G1 (SoFi reachable from production); the must-fix part of G8 (forbidden content classes, the conformance-Invalid stall, the four unenforced bounds, setup predicates); G9 (remove SMT eviction); G10 (remove the sticky reject).
- **Out of beta, declared:** G3 (the candidate and guard state model). Owner direction, 2026-09-23: every kind of state rests on required base terms — a resource, a guard, a consumption key derived from parent and resource, and the consumed set — and specialized kinds (money, SoFi, offline, and later ones such as game state) are built on those base terms and added by software update; beta runs on the existing specialized mechanisms, and nothing added for beta may conflict with the base terms; the rest of G8 (aux candidates, Core naming SoFi operations, the drop rung, which waits for Part III).
- **In beta (owner, 2026-09-23):** G16 (sealed, append-only spool).
- **No beta work:** G11 (legacy DLV manager, dBTC only; SoFi vaults consume through successor cells, final with G2).

## 5A Skeleton rewire checklist

The skeleton (step 6 of the working flow) removes what the specifications forbid. Every feature that used a removed path is rewired onto the conforming one in implementation (step 8). A row is ticked only when that feature has been exercised end to end, not when it compiles. Nothing that works today is dropped (owner, 2026-09-23).

| Done | Feature | What the skeleton removed | Rewired onto |
|---|---|---|---|
| [ ] | Genesis publication and device-tree evidence (`publish_genesis_to_nodes`, `register_device_in_tree`, `ensure_device_in_tree`, the device-tree evidence quorum check) | The registry publish endpoint, which overwrote | The immutable store: content-addressed, write-once |
| [ ] | Identity tips | The overwrite primitive | A keyed cell per device: each tip appended, the latest read |
| [ ] | Vault policy objects (`api/vault/policy.rs`) | The overwrite primitive | The immutable store |
| [ ] | Recovery capsules | The capacity-refusing overwrite | The immutable store for capsules, a cell for the latest pointer |
| [ ] | SDK object reads and writes (`storage_io` and others) | The legacy object store | The immutable store and cells, per call site |
| [ ] | b0x send and receive | Writer and reader authorization, tokens; the node-side read flag (ack), the status route, the unpositioned retrieve and expiry (owner, 2026-09-23) | An append-only spool read from a position; what a device has consumed is kept on the device (`client_db::b0x_consumed`: consumed ids, and a per-node read position that only moves forward); sender outbox rows complete on the verified acceptance, with no node check |
| [ ] | Device registration (identity directory) | Token issuance and reissue | The same directory without tokens |
| [ ] | Every cell write and read (economic-root register, faucet reserve, SoFi cells) | The copy rule and the copy writers | Route-chain writes (`RouteSeats`), Core chain evaluation (`route_chain`) |
| [ ] | SoFi resolution and conformance | The third predicate value; the in-hand check is not written yet | Binary predicates, acquisition-layer retries, in-hand checks before any read |
| [ ] | Token creation and burn | Mint, signer-authorized issuance | Release at creation (a new credit source replacing the authorized-issuance arm), burn |
| [ ] | Transferable check | Not wired before | Token policies in validation evidence; the check at every transfer, vault creation and SoFi leg |
| [ ] | Frontend: accounts, token creation | Mint, the old policy fields | Burn only; genesis supply, burn flag, threshold |
| [ ] | Tests | Fixtures built on removed fields and routes | Rewritten against the new types and the real node |
| [ ] | SoFi routes (G1) | Nothing reached SoFi | `handlers/sofi_routes.rs` (eight routes, SoFi §27) calling `sdk/sofi_flow.rs` orchestration entries that run the §28–§33 stages; the frontend SoFi screens on those routes |
| [ ] | SetupValid in RouteValidation (G8) | Never evaluated | Setup envelopes in validation evidence; `setup_valid` per leg (encoding, ρ, signature, ClaimRef, identity and vault rules), with a named test that fails when it is removed (`realized_requires_valid_setup`) |
| [ ] | Bounds of SoFi §18.4 (G8) | Four never enforced | `conformance_bounds` (object size, signed envelopes, aggregate fetch) and the provenance fanout in `verify_manifest_provenance_index`; named tests for each; confirm every admission path calls the manifest check |
| [ ] | Offline, end to end | Nothing (the unused `0x0028` re-entry credit and its stub were removed, owner 2026-09-23: offline value is the device's designated offline accounting, and moving it back online is a free state change in the device's own transition) | Exercised end to end: load, spend over Bluetooth, receive, unload, then spend the result online |
| [ ] | SDK test harness | The fake storage node (`test_support/fake_node.rs`) and the in-process fakes built into the I/O layer: in every test build, each storage call in `storage_io` (cells, objects, indexes, reads and writes) answered from `fake_registers` / `fake_fleet` and never reached a node (owner, 2026-09-23: no fakes) | Real nodes in process (`test_support/real_nodes.rs`: the node's own code on SQLite, its own register incarnation, its pinned set, and exactly the binary's app via `dsm_storage_node::build_app`); the two-device harness on them; every test that used the fakes or their fault injection rewritten on real nodes |
| [ ] | Encrypted spool payloads (G16) | Nothing was encrypted | Per-step message key from each step's Kyber shared secret under its own domain tag; transfer bodies, replies, evidence halves, checkpoints and `message.send` text sealed with XChaCha20-Poly1305; exercised end to end with a node holding only ciphertext |
| [ ] | Tip-mirror leaves (G16) | Unchecked | Confirm per-relationship leaves are stored encrypted, as storage §8 requires; seal them if not |
| [ ] | What a transfer publishes (G16) | Unchecked | Audit every object an ordinary bilateral transfer writes to shared storage against "only the parties to a relationship hold its bytes" |
| [ ] | Device directory | The node's first-write-wins device table, its routes, and the SDK's quorum lookup and token registration | Self-signed entries in a keyed cell (`dsm::core::identity::directory`, `sdk::device_directory`): each device publishes its own AK-signed entry; senders keep the entry whose AK hashes to the device id and whose signature verifies, highest counter first; every caller of the old lookup moved to `read_entry` / `publish_entry` |
| [ ] | Sealing's key and store | — | `sealed_bytes_for` seals once with the recipient's Kyber key from its verified directory entry and keeps the bytes (`client_db::b0x_sealed`); `open_sealed` decapsulates with this device's Kyber secret |
| [ ] | Vault genesis acceptance | Never built: SoFi §28 step 5 names `genesis_accepted`, no such function exists, and its `GenesisError` type is orphaned in `sofi/lineage.rs` | `accept_vault_genesis` in `fetch_vault_genesis`: the signed creation bound to the owner transition, the committed market policy re-derived, the pair ordered, both token policies permitting a market leg; `Resolved::Unavailable` there becomes a network failure, not "no genesis" |
| [ ] | Transferable check on every leg | Never called | Token policies in `Evidence.token_policies` (both tokens of every vault, intermediate ones included); `market_legs_permitted` per DLV core in `validate` |
| [ ] | Fleet redeploy (GCP) | The deployed fleet runs the old node: device registration, read acknowledgement, plaintext spool, node-side tables | Rebuild the `dsm-storage-node` image and redeploy every node (`dsm_storage_node/deploy/`: Docker Compose with Postgres 15 on the GCP VMs) in the same release as the app; the migrations drop the devices, auth, payment and registry tables and the spool's ack columns on the live databases. Wipe or keep the Postgres volumes is not yet decided; a wipe gives every node a new register incarnation, so the pinned set in the node configs and in the app's `dsm_env_config.gcp_beta.toml` is regenerated and shipped with the app. Terraform provisions 5 nodes (`terraform/gcp/main.tf`, `node_count = 5`), matching the 5 configs; the "6 nodes" in `provision_gcp.sh`'s banner is stale text to correct |
| [ ] | Formal models (G15) | The successor-cell, fulfillment and reserve models encode the copy rule ("LeaderHeld and two other members hold x"); `lean4/DSMTokenIssuance.lean` models minting and signer-authorized issuance, which no longer exist | Route-chain models written: `tla/DSM_RouteChain.tla` (chain uniqueness, nesting, stability, survival of two lost seats; three mutation configs that must fail, listed in `tla/README.md`) and `lean4/DSMRouteChain.lean` (compiles on the pinned Lean 4.23.0; chain uniqueness proved; stability and loss survival stated). Remaining: `DSM_SofiSuccessorCells`, `DSM_SofiFulfillment`, `DSM_NativeReserveRelease` and their Lean files take finality from the route chain; `DSMTokenIssuance.lean` rewritten for release at creation; the stated properties proved and every config run under TLC |

## 6 CODE → SPEC

What the backend does that no requirement asks for, or that a requirement forbids. §4 G4 covers the node's legacy store; it is not repeated here.

### 6.1 Stand-ins on production paths

| Location | What it does |
|---|---|
| `dsm_sdk` · handlers/response_helpers.rs · `response_headers` | Every AppRouter response envelope carried `chain_tip: vec![0u8; 32]` and a zero message id; `pack_bytes_ok` callers passed a zero schema hash. Resolved on `fix/beta-skeleton-compile`: a local response carries no headers, no message id and no schema hash (neither the frontend nor Kotlin reads them). |
| `dsm_storage_node` · api/infra/rate_limit.rs · `check_rate_limit` | Returned `Ok(())` unconditionally, mounted on every public route; `RateLimiter::new` and `::new_bypass` were the same empty struct. Resolved on `fix/beta-skeleton-compile`: the limiter, its layer, `benchmark_mode`, the `--benchmark-mode` flag and the unread `enable_rate_limits` config keys are deleted (owner, 2026-09-24). |
| `dsm_sdk` · ble/mod.rs · `WriteCharacteristic` arm | `{ /* no-op for now */ }`, then reported "write queued to platform"; every other arm acknowledged without a platform call. Resolved on `fix/beta-skeleton-compile`: the `ble.command` route, the `BleBackend` registry, `AndroidBleBackend`, the always-compiled `force_no_backend_for_tests` switch and the README claim are deleted. No frontend or Kotlin caller existed; BLE runs through `bluetooth/`. |
| `dsm_sdk` · sdk/storage_node_sdk.rs · `start_health_monitoring` | A loop that checks nothing ("In a real implementation … For now"), started by `StorageNodeSDK::new`. |
| `dsm_sdk` · sdk/identity_sdk.rs · `load_stored_identity` | Did nothing ("For now, we rely on …"); `IdentitySDK::new` made a fresh keypair per pairing request. Resolved on `fix/beta-skeleton-compile`: `IdentitySDK` is deleted; `identity.pairing_qr` / `pairing_compact` build from `AppState` (the QR had carried a fingerprint of the literal `"local"` and network `"main"`; it now carries the committed network and no fingerprint). `identity.transport_headers_v3` no longer initializes the SDK context with the genesis hash as entropy. |
| `dsm` · core/token/policy/policy_validation.rs · `validate_token_type_compatibility`, `validate_metadata_fields`, `validate_owner_constraints` | Empty "hook points" ("Kept permissive for now"). Resolved on `fix/beta-skeleton-compile`: deleted with their calls and the dead `_errors` parameter of `validate_mode_specific`; `validate_token_metadata` reports what it checks (the anchor's form). |
| `dsm` · core/token/policy/policy_enforcement.rs · `SupplyCap` arm | Compares against a `circulating` figure the caller supplies; the SDK producer sums only this device's chain. |
| `dsm_storage_node` · api/vault/policy.rs · `anchor_to_db_key` | Hex-encodes the policy anchor as a DB key. |
| `dsm_storage_node` · api/objects/store.rs (lines 36–88) | A second hand-written Base32 Crockford codec. |
| `dsm_sdk` · sdk/unilateral_ops_sdk.rs:370 | `tx_hash = tx_id` ("hash proxy for now") in a stored display record. |

### 6.2 Stand-ins with no production caller

| Location | What it does |
|---|---|
| `dsm_sdk` · sdk/core_sdk.rs · `verify_and_add_contact`, `verify_genesis`, `extract_public_key_from_genesis` | `verify_genesis` is `Ok(!genesis_hash.is_empty())`; the "public key" is the first 32 bytes of the genesis hash. Public on `CoreSDK`; no callers. |
| `dsm_sdk` · sdk/token_mpc_sdk.rs (`TokenMpcSDK`) → sdk/token_sdk.rs · `execute_simplified_bilateral_transfer`, `complete_bilateral_transfer` → `fetch_and_cache_genesis` → sdk/counterparty_genesis_helpers.rs · `fetch_genesis_state` | `dummy_material`; `can_transfer_token` returns `Ok(true)` after one flag check; `fetch_genesis_state` synthesizes an MPC genesis over fixed nodes `n1`, `n2`, `n3` ("In a real implementation"). The whole chain has no production caller. |
| `dsm_sdk` · sdk/storage_node_sdk.rs · `put_with_replication` | "For now, just use the primary node"; returns `Ok` below the required replica count. No callers. |
| `dsm_sdk` · sdk/storage_node_sdk.rs · `submit_b0x_entry` | "For now, just send the transaction bytes". No callers. |
| `dsm_sdk` · sdk/genesis_publisher.rs (lines 150–182); sdk/identity_sdk.rs · `create_genesis`, `provision_device` | Legacy MPC genesis with hard-coded nodes and a non-protobuf serializer. Resolved on `fix/beta-skeleton-compile`: both files deleted. |
| `dsm_sdk` · storage/bilateral.rs · `persist_bilateral_transaction` | Writes `""` for sender and receiver ("empty for now"). Test callers only. |
| `dsm` · types/state_types.rs · `NonInclusionProof::from_smt`, `verify` | "For now, return a proof with the root hash"; empty path. Resolved on `fix/beta-skeleton-compile`: deleted (no users), with `MerkleProof::from_smt_proof` (zeroed fields, no callers) and `Identity::get_proof` (a "not yet migrated" refusal, no callers). |
| `dsm` · commitments/smart_commitment.rs · `new_conditional`, `new_compound`, `new_compound_or` | "Placeholder commitment scaffolding op (empty token, zero amount)". Resolved on `fix/beta-skeleton-compile`: each takes the operation it commits, and recipient and amount come from it; the integration tests that discarded their results now assert. |
| `dsm` · vault/asset_manager.rs · `validate_transfer` | Read a "balance" string from an unauthenticated metadata map. Resolved on `fix/beta-skeleton-compile`: deleted with its tests. |
| `dsm` · core/bridge.rs · `handle_bilateral_offline_send` | "ignore other op kinds for now". Test callers only; offline is a dependency boundary this round. |

### 6.3 Code with no production caller

| Location | Note |
|---|---|
| `dsm` · core/state_machine/transition.rs · `create_next_state`, `apply_transition`, `verify_transition_integrity`, `apply_token_balance_delta` | Legacy `State` path, a second public way to produce state outside `DeviceState::advance` (MR-DSM-0243, 0244). Deleted with the rest of the layer (§6.10). |
| `dsm_sdk` · sdk/receipts.rs · `verify_stitched_receipt`; `dsm` · verification/receipt_verification.rs · `verify_stitched_receipt` | The only code shaped like candidate/guard checking (`ForkCandidate`). No handler calls it. |
| `dsm_sdk` · sdk/dlv_pre_commitment_sdk.rs · `DlvPreCommitmentSdk` | No handler callers. Deleted (§6.10). |
| `dsm_sdk` · sdk/smart_commitment_sdk.rs · `SmartCommitmentSdk` | No callers. |
| `dsm` · core/verification/identity_verifier.rs; types/identity.rs; types/state_types.rs (second `IdentityAnchor`) | `IdentityVerifier`, `IdentityClaim`, `IdentityAnchor`. No production callers. |
| `dsm` · economic/issuance.rs · `check_market_leg_permitted` | No callers (MR-SOFI-0311). |
| `dsm` · ccb/state.rs · `VaultStateV2.iteration_budget` | Only ever `None`; never read (MR-DSM-0181). |
| `dsm_storage_node` · api/identity/authenticate.rs · `authenticate_envelope_smart_policy` | No production caller. |

### 6.4 Tests that report green without testing the shipped path

| Location | Defect |
|---|---|
| `dsm_storage_node` · api/identity/device_api.rs (three tests), api/transport/b0x.rs · `v2_b0x_routing_and_ack_scope_end_to_end`, api/vault/recovery.rs (line 148), api/vault/slot.rs (line 105) | Returned early unless `DSM_RUN_DB_TESTS=1`. Resolved on `fix/beta-skeleton-compile`: no test skips; the b0x tests are rewritten on the Postgres test store (a sealed envelope round-trips byte for byte and opens with the recipient's key) and the slot test runs there too. |
| `dsm_storage_node` · tests/immutable_store_round_trip.rs, tests/paidk_gating.rs, tests/identity_milestone_e2e.rs | `#![cfg(feature = "local-dev")]`: they tested `db/sqlite.rs` only. Resolved on `fix/beta-skeleton-compile`: the SQLite backend and `local-dev` are deleted (owner, 2026-09-24); the suites and the store tests that lived in `sqlite.rs` run on Postgres (`db/store_properties.rs`). |
| `dsm_storage_node` · tests/paidk_gating.rs · `t_b_paid_device_accepted` | Sets the paid flag directly; the distinct-operator count in `store_payment_receipt` is never exercised. |
| `dsm` · tests/sofi_v8_independent.rs · `closure_index_enforces_bounds_order_and_current_e_exclusion` | Iterates `CLOSURE_FORBIDDEN_CONTENT_CLASSES` itself, so a missing class cannot fail it (MR-SOFI-0176). |
| `dsm` · tests/sofi_v8_independent.rs · `bounds_are_the_ruled_values` | Asserts constant values of bounds nothing enforces (MR-SOFI-0163, 0180). |
| `dsm` · vault/limbo_vault.rs · `vault_state_limbo_ne_active` | Compares enum discriminants; nothing exercises the terminal-state refusal (MR-DSM-0175). |
| `dsm` · core/state_machine/transition.rs tests | Exercised a path production does not run. Deleted with the layer (§6.10). |

### 6.5 Found while making the skeleton compile (branch `fix/beta-skeleton-compile`, 2026-09-23)

Against the branch, not the §1 pin. Resolved items state what replaced them; open items are holes, not stand-ins.

| Location | Finding | State |
|---|---|---|
| `dsm` · economic/provenance.rs · `verify_genesis_release` | A policy commit named no creator, so any device holding published policy bytes could `CreateToken` the same token and release its whole genesis supply again (MR-SOFI-0307). | Resolved by SoFi Amendment S8: the policy commits its creator, only the creator's transition releases it, and the creation inserts a `0x0060` record from zero. Named tests with mutation controls: `a_genesis_release_of_another_creators_policy_is_refused`, `a_token_is_created_once_on_its_creators_lineage`, `a_creation_witness_without_its_record_is_refused`. |
| `dsm` · sofi/validation.rs · `setup_valid` | The ClaimRef conjunct of SetupValid (SoFi §16) was not checked; validation evidence carried no claim. | Resolved by SoFi Amendment S9: `AcceptedClaim`, produced only by lineage validation, is carried in `Evidence.accepted_claims`. Named tests with mutation controls for every conjunct of `setup_valid` and of `market_legs_permitted`. |
| `dsm` · economic/lineage.rs · `advance_validated` | Never checked that the registered claim names the trader under validation. | Resolved: `RegisteredClaimNamesAnotherTrader`, test `a_registered_claim_of_another_trader_is_refused`. |
| `dsm` · route_chain.rs · `evaluate` | Reported two impossible states as missing evidence, counted only the first copy per seat, and its callers re-recognized the held bytes and invented an answer when that failed. | Resolved: the recognized object is returned; every rule of storage §9 has a named test and a mutation control. |
| `dsm` · route_chain.rs · `CellEvidence`; economic/native_reserve.rs, economic/register.rs, sofi/exercise.rs, sofi/registration.rs | The route, namespace and key of a cell came inside the evidence the reader handed Core, so Core evaluated whatever route the caller named (storage §9 route rule 1: the writer and Core compute the route). | Resolved: `RoutedCell::new` derives the cell from the seed and the members, refusing members that do not re-derive the committed set id; each cell kind has a handle only Core builds (`SuccessorCell`, `RootCell`, `AttemptCell`, `PositionCells`); evidence carries seat reads only. Mutation controls: `a_cell_is_routed_only_over_the_committed_set`, `a_successor_cell_is_routed_over_the_set_its_parent_commits`. |
| `dsm` · economic/peer_lineage.rs · `PeerEvidenceFetcher::register_cell` | The fetcher returned the register cell's final bytes, so the reader, not Core, decided which claim held each position of a peer's lineage. | Resolved: the fetcher returns the seat reads of the `RootCell` the walker names, over the network's pinned register set resolved before the first read; the walker evaluates the chains and reads only a final claim. Claims naming other coordinates are not recognized at the cell (storage §9 rule 3). Tests with mutation controls: `a_claim_that_is_not_final_decides_nothing_yet`, `a_claim_naming_other_coordinates_never_holds_the_root_cell`. |
| `dsm` · economic/peer_lineage.rs · step 5; economic/provenance.rs · `ProvenanceResolver::native_reserve_release` | Every validation error of a peer's step was reported `Invalid`, including a nested peer lineage, a token policy or acceptance evidence that could not be fetched, and a reserve release the resolver could not read (an `Option`, so an outage read as "no release"). A network outage anywhere below a step branded an honest peer as a forger, terminally (storage §4: a fact not established is never read as its negation). | Resolved: the resolver returns why a release is not established; `step_failure` classifies every validation error exhaustively, keeping the class of each failure met below the step. Test with mutation control: `a_step_failure_keeps_the_class_it_was_established_in`. |
| `dsm` · economic/lineage.rs · `EconomicValidationError::OfflineBoundaryWriteSetNotYetSpecified` | A refusal standing in for the offline-boundary write set, which is not built. | Open: offline is a dependency boundary this round. |
| `dsm` · route_chain.rs · `CommittedAt` | Storage §14 rule 3: a verifier checks a ByteCommit's chain link. `CommittedAt` carries one mirrored ByteCommit and its proof; the link to the member's previous ByteCommit is not checked. | Open: the evidence shape needs the mirrored predecessor, and §14 does not say how far back a verifier walks. |
| `dsm` · economic/provenance.rs · `ReserveReleaseWin` | Public fields: any caller can assemble the "final release" a credit's provenance check then relies on for finality. The SDK builds it from its own walk memo. | Open. |
| `dsm` · types/device_state.rs · `advance` | A credit-direction transfer "gate" was an empty `if` under a comment describing a refusal removed in #966; the conservation comment claimed a commit "proven distinct from every existing asset" while only builtins were checked; a zero-supply creation was accepted (SoFi §50). | Resolved: empty block removed, comments state what the code checks, zero supply refused. |
| `dsm` · types/device_state.rs · `advance` | Verifies no signature on `AdoptToken` or `CreateToken`; only SoFi operations are signature-checked at the accepting transition. | Open. |
| `dsm` · economic/provenance.rs · `ValidatedPeerTransition::single_root_for_test`, `resolved_sofi_for_test` | `feature = "testing"` constructors of a validated peer transition, with a zero manifest address, bypassing the peer walk. | Resolved (§6.7): deleted with the `testing` feature and the tests built on them. |
| `dsm` · types/device_state.rs · `admitted_faucet_claim` | Testing helper named "admitted" that advances a faucet claim with no release evidence and no admission. | Partly resolved (§6.7): `cfg(test)` only, so no other crate can reach it; the SDK test that used it runs on real faucet claims. |
| `dsm` · sofi/registration.rs · `names_fulfillment_key` | Recognition at `K_ful(q)` depends on which precommits the reader fetched: a candidate whose P is not in hand is skipped, so a later candidate can read as the first recognized value. Storage §9 rule 3 needs recognition decidable from the bytes. | Open: spec question. |
| `dsm` · economic/peer_lineage.rs · memo start | Rehydrated a peer's memoized start through `ValidatedEconomicRoot::rehydrate_from_admitted_store`, whose contract excludes peers, and made the memo carry a claim nothing read. | Resolved: `ValidatedEconomicRoot::from_verifier_memo`, crate-private, one caller (the walker), pinned by `ci/sofi_validated_root_constructors.sh`; `ValidatedStart` carries position and root only. |
| `dsm` · route_chain.rs · `evaluate` | Counted the positions holding any valid link, so links on two different chains could add up to `Final`. | Resolved by the storage §9 ruling of 2026-09-23: a value is final on three links of ONE chain; a carried link counts only if its own copy carried exactly the earlier positions. Completion proofs (`completion_proof`, `check_completion_proof`, `completion_digest`) built to the same ruling. Tests with mutation controls: `only_links_of_one_chain_count_toward_final`, `a_copy_whose_carried_links_are_not_one_chain_does_not_count`, `a_completion_proof_is_checked_against_the_seats`, `the_completion_digest_is_the_proofs_fields`. |
| `dsm_sdk` · SoFi unlock | SoFi Amendment S10 and storage §9 rule 11: the client keeps the completion proof of each `Final` its unlock relies on, and Core checks it against the seats. | Partly resolved: `route_seats::keep_completion` keeps the proof of every `Final` read at an attempt cell, a registration pair and a reserve release. Open: nothing yet presents a kept proof where an unlock relies on it. |
| `dsm` · sofi/validation.rs · `EvidenceNeeds` | Names no token policies and no accepted claims, though `validate` consumes both. | Open. |
| `dsm` · tests/economic_authorized_issuance.rs | Deleted with the signer-authorized issuance it tested. §8 rows MR-SOFI-0310, 0312, 0316, 0318, 0326 and 0327 cite it. | Those rows are stale against the branch. |
| `dsm_sdk` · handlers/unilateral_impl.rs, sdk/unilateral_ops_sdk.rs, `UnilateralHandler` (SDK bridge and Core bridge) | `unilateral.sync` read spool entries and recorded them consumed without applying them, so a transfer it touched was never received; before genesis `UniImpl` installed a zero device id and a "disabled" ops SDK that refused everything. No client sends a `unilateral.*` invoke. | Resolved: the handler, its ops SDK and both bridge traits deleted; a `unilateral.*` invoke reaches the app router and is an unknown method. |
| `dsm_sdk` · handlers/storage_routes.rs · `storage.sync` | A request that did not decode ran as "pull, push, limit 100"; `processed` was always 0, and the frontend refreshes the wallet only when it is positive; each call registered the device for auth tokens; failures of acceptance recovery and outbox collection were logged and dropped; `storage.status` reported the transaction count as `last_sync_iter`. | Resolved: strict decode (`limit` 0 is the wire default, above 200 refused); `processed` counts transfers completed, deltas finalized on and checkpoints applied; every sweep failure is in `errors`; `last_sync_iter` is the count of completed syncs (`client_db::storage_sync_runs`, its producer). |
| `dsm_sdk` · sdk/b0x_sdk.rs · `push_pending_bilateral_messages` | Resubmitted BLE bilateral sessions to the spool with a "stopgap" seq, a random submission id, empty canonical bytes and a fallback signing key, dropping every failure. | Resolved: deleted. |
| `dsm_sdk` · sdk/b0x_sdk.rs · `retrieve_from_b0x_v2` | Ignored its limit; with every node marked failed it answered an empty inbox; it blocked the executor inside an async function. | Resolved: the limit is gone (each node is read at most `MAX_RETRIEVE_PAGES_PER_NODE` pages; callers bound the items); no reachable node is an error. |
| `dsm_sdk` · sdk/contact_sdk.rs; `dsm` · core/contact_manager.rs | Seven add paths, one of them (a genesis payload) reached by nothing; contacts stored with no Kyber key; default storage nodes from an environment variable; a failed SQLite write swallowed on one path. `DsmContactManager.storage_nodes` and `InitialSetupClient` were written and never read. | Resolved: one add path, `add_contact_from_directory`, from the device's self-proving directory entry (AK and Kyber key) held by at least three members; `ContactManager::open` loads strictly; the dead Core field removed. |
| `dsm_sdk` · storage/client_db/types.rs · `ContactRecord::to_verified_contact` | A malformed chain tip became "no tip" and bad lengths gave `None`; every caller skipped the contact silently. | Resolved: a malformed row is an error; the four copies of the BLE handler's just-in-time contact sync are one strict helper. |
| `dsm_sdk` · handlers/storage_routes.rs · `storage.status`, `storage.nodeHealth`, `storage.connectivity` | Probed the configured endpoints; node names and regions came from a hard-coded address map of a retired cluster; the connectivity probe registered the device for auth tokens; a failed metrics scrape read as zero counters. | Resolved: the pinned set's members by member id; scrape failures and unexposed counters are named in `last_error`. The counters still encode "absent" as 0, which proto3 cannot distinguish: a wire gap. |
| `dsm_sdk` · handlers/inbox_routes.rs · `inbox.startPoller`, `inbox.stopPoller`, `inbox.resume` | Answer `StorageSyncResponse{success: true, pulled: 0, …}` though they sync nothing. | Open: a lifecycle invoke needs a response of its own (a wire decision); Kotlin ignores the answer. |
| `dsm_sdk` · handlers/storage_routes.rs · `storage.addNode`, `storage.removeNode`; network.rs · `auto_assign_storage_node` | The client edits its own node list, while every protocol path uses the network's pinned set (storage §9: `S` is committed). | Open: remove with the frontend sweep; the storage panel calls them. |
| `dsm_sdk` · recovery (sdk/recovery_sdk.rs, handlers/recovery_routes.rs, handlers/recovery_impl.rs) | Stored its objects under mutable node paths whose node-side bind-once and fork checks storage §6 forbids; the routes and the pipeline derived different tombstone-notice keys, so a posted tombstone was never found; a contact's tombstone ACK was its unsigned device id, counted by presence. | Resolved: each object lives in its keyed cell (`dsm::recovery::RecoveryCell`) and the reader decides — the one distinct anchor whose genesis binding verifies under the device's directory AK (two are equivocation); the PDSMT chain verified from the genesis head, a fork refused; the leaf set that verifies against its head; one derivation of every key; the ACK is `ContactTombstoneAck`, signed by the contact's AK (`TAG_DSM_RECOVERY_ACK`, declared for it and unused until now). Named tests with mutation controls: `a_contact_tombstone_ack_verifies_only_as_signed` (signature check removed → red), `tampered_device_signature_fails` and `wrong_genesis_signing_pubkey_fails` (genesis binding's signature check removed → red), `every_object_has_its_own_cell` (two kinds sharing a kind byte → red). Open: `build_and_publish_pdsmt_head` has no production caller, so no device posts heads and recovery cannot gather a counterparty's evidence; `RecoveryTombstoneResponse.tombstone_receipt` allows 4096 bytes, below one SPHINCS+ signature. |
| `dsm_sdk` · sdk/sofi_flow.rs (G1) | The eight SoFi routes called entries that did not exist. | Built: §28–§33 over the producers, the Core transition and the resolution ladder. Core's `realize_root`, `swap_vault_post`, `close_vault_post` and `Policies::resolve` are public so producer and verifier compute with one function (mutation control: `realize_root` returning the pre-root turns `a_well_formed_swap_is_valid`, `a_well_formed_close_by_the_origin_owner_is_valid` and six others red); `draft_*` derive `R_realize` and `R_void` instead of taking them (they needed `E`, which only the draft computes); `Publication::VaultGenesis` and `VaultPolicy` publish what the verifier fetches. Open: vault discovery for a setup is out of band (path search runs over the vaults the device is set up with); relaying walks the trader's lineage to `p` to route `K_ful(q)`, and the peer walk refuses conditional claims (E1c-3), so a position whose predecessor is a SoFi position cannot be relayed by a third party. A one-hop trade is exercised end to end (§6.7). |
| `dsm_sdk` · sdk/bitcoin_tap_sdk.rs | Used the removed path-keyed store (`put_bytes`, `get_bytes`, `list_objects`, auth resolution); ten compile errors kept the SDK library, and everything built on it, from building. | **Stubbed, owner-authorized 2026-09-24, fenced `BITCOIN STUB`:** every production dBTC storage call returns `NotImplemented("BITCOIN STUB …")` and stores, reads, lists or deletes nothing; the removed store's three result shapes are kept as local types inside the fence. Bitcoin is out of this round (owner). |
| `dsm_sdk` · handlers/app_router_impl.rs · `message.send`; ingress.rs | `message.send` filled a malformed chain tip, a missing local genesis and a non-contact recipient's genesis with zeros; bootstrap registered the device for auth tokens and republished a registry entry. | Resolved: explicit errors; both registrations deleted (the directory entry is published by identity publication, resumed at startup). |

### 6.6 Independent false-success audit (2026-09-24)

An audit of the uncommitted branch listed 14 findings (F01–F14) and two migration follow-ups (K01–K02). All are resolved on `fix/beta-skeleton-compile`; the rows above state each resolution. In short: `DSM_SDK_TEST_MODE` is gone from production code (F01); `AppState` writes return typed errors, update memory only once the disk holds the change, and a corrupt state file is refused rather than read as "no identity" (F02); the fake BLE backend and its always-compiled test switch are deleted (F03, F12); the no-op rate limiter is deleted (F04); `TokenOps::verify_token` (F05), `NonInclusionProof` (F06), the empty policy hooks (F07), `IdentitySDK` and the genesis publisher (F08, F09), the orphan predictor registration (F11) and `AssetManager::validate_transfer` (F14) are deleted; the conditional and compound commitments commit the caller's operation (F10); the safety script no longer reports TLA+ it skipped, TLA+ being the Formal Validation job's (F13); the SDK harness and CI run storage nodes on Postgres only (K01, K02).

Found beside them and resolved the same way:

| Location | Finding | State |
|---|---|---|
| `dsm_sdk` · handlers/misc_routes.rs | `debug.dump_state` logged identity and contacts behind a caller-chosen string; `debug.trigger_genesis` did nothing. No caller. | Deleted. |
| `dsm_sdk` · storage/client_db/export.rs, `state.export`, `state.info` | The remains of the deleted backup feature, with read errors turned into zero counts. No caller. | Deleted. |
| `dsm_sdk` · sdk/app_state.rs · `handle_app_state_request` | Answered `""` for `device_id`/`genesis_hash` and `"0"` for `chain_tip`; returned errors as values; let a `prefs.set` flip `has_identity`. | Replaced by `get_pref` (absent is `None`) and `set_pref` (typed error); preferences cannot reach the identity flags. |
| `dsm_sdk` · sdk/session_manager.rs | A stored lock setting that was neither `true` nor `false` read as the in-memory default; lock writes were discarded; the snapshot envelope carried zero headers and a zero message id. | A malformed setting is an error; an unlock takes effect only once persisted; the snapshot is framed like every local answer; JNI reports the error. |
| `dsm_sdk` · handlers/app_router_impl.rs | A boot hook purged retired preference keys "so the next release can drop this hook". | Deleted (beta takes clean cuts). |
| `dsm_sdk` · init.rs | Rewrote the AK into `AppState` when missing, for identities from before key persistence. | Replaced by a check that the held AK is the one the wallet derives. |
| `dsm_sdk` · ingress.rs · `prime_identity_app_state` | Installed the empty tree's root as the identity's SMT root. | Installs the root the genesis record holds. |
| `dsm_sdk` · handlers/recovery_impl.rs | Bound a recovered identity with an empty AK when none was held and a zero SMT root when the capsule's was not recorded, swallowing the read error. | Each is an error. |
| `dsm_storage_node` · tests/fanout_dev_replication.rs, tests/integration_submit.rs | One hashed the same bytes twice; the other asserted properties of a string literal. Neither touched node code. | Deleted. |
| `dsm_sdk` · handlers/identity_routes.rs tests, sdk/app_state.rs tests | Round-tripped prost messages, asserted a struct's own fields, accepted either of two outcomes, or returned early when not spawned. | Replaced by tests of the routes and of persistence (reload, failed write, corrupt file); the child test is ignored and run by its parent. |
| `dsm_sdk` · handlers/identity_routes.rs · `identity.devtree.snapshot` | Answered "not built yet (owner ruling pending)": a refusal in place of the work. | Arm deleted; the route is a visible hole until the device tree store is built. |

### 6.7 Found while completing the skeleton (branch `fix/beta-skeleton-compile`, 2026-09-24)

Against the branch. Tests named here run on devices created as wallet creation creates them, on the storage node's own code over Postgres; a mutation control names the test that goes red when the gate is removed.

**Resolved**

| Location | Finding | State |
|---|---|---|
| `dsm_sdk` · sdk/sofi_advance.rs · `resolve_pending_position`; `dsm` · sofi/lineage.rs · `advance_resolved` | A Realized position installed `P.R_realize` in the admitted root and the leaf cache, and persisted the head with its old balances. The trader's head kept the ERA it paid, and the token it received could not be spent (`advance` underflow) while the tree held it (SoFi §19.5, §38: after resolution the root `advance_resolved` selects is the state). | `advance_resolved` derives `ResolvedBalances` from the settlement and the evidence its verdict used (`trader_balance_changes`: the balance before, from the evidence's pre state; after, bound to the value `T°` states under `P.R_realize`); a Void carries none. `DeviceState::with_resolved_position` applies them only to a head holding every `before`. `CoreSDK::admit_resolved_sofi_position` is the only admission of a resolved SoFi position (the generic admission refuses one); it applies the balances in the admission transaction and the head in memory is the head made durable. Tests: `a_realized_position_moves_exactly_the_balances_its_realize_root_holds`, `a_void_position_moves_no_balance`, `a_head_that_does_not_hold_the_pre_balances_takes_no_resolution` (pre-balance check removed → red), `node_e2e_tests::a_sofi_trade_executes_end_to_end` (ERA 190, TKN = `constant_product_output(10, 100, 1000, 30)`, head equal to the admitted leaves; balances left off the admitted head → red). |
| `dsm_sdk` · sdk/route_seats.rs · `value_of`; sdk/sofi_register.rs · `read_registration` | Read seat-log entries as raw values. Seat logs hold `RouteEntry`-encoded copies, so no SoFi position ever registered. | `carried_values` decodes each entry; the registration reads the values it carries. |
| `dsm` · types/device_state.rs · `validate_conservation` | No `SofiVaultCreate` arm: every vault creation was refused as a non-balance operation applying deltas, so `sofi.createVault` could never succeed. | Exactly the debits of the two funded legs, from the canonical creation record. Test: `a_vault_creation_debits_exactly_its_two_funded_legs`. |
| `dsm_sdk` · sdk/faucet_claim_flow.rs · `WalkStop::LeaderHeld` | Returned an error forever: a release whose chain was cut short after its leader stalled the reserve for every claimant (storage §9: any party may continue a chain). | The release is carried and the walk resumes. Tests: `a_release_cut_short_after_the_leader_is_carried_by_the_next_claimant_and_bricks_nothing`, `a_claim_cut_short_resumes_on_its_own_release_byte_identically`. |
| `dsm_sdk` · sdk/route_seats.rs · `write_recorded` | A recorded chain that every position closed short of three links was continued from past the route's end, so its writer could never finish its own value. | A closed-short recorded write starts a new chain from the leader's record (storage §9). |
| `dsm_sdk` · sdk/b0x_sdk.rs · `deliver` | Quorum was `quorum_k.min(healthy endpoints)`: members the circuit breaker marked lowered the bar, and delivery to K−1 members reported success. | K over all members; the breaker only orders the attempts. Test: `delivery_below_the_quorum_is_refused_however_many_members_are_marked_failed` (the `min` restored → red). |
| `dsm_sdk` · handlers/system_routes.rs · `install_wallet_genesis` | `merkle_root.unwrap_or([0; 32])`: a v3 genesis carries no merkle root, so every wallet and its genesis record held a zero SMT root. | The installed head's root. Test: `the_genesis_answer_names_the_identity_the_wallet_installed`; JNI `extractGenesisIdentity` reads the answer strictly. |
| `dsm_sdk` · handlers/response_helpers.rs and its readers | Local answers are headerless; they were decoded with the wire decoder (headers required) in the `storage.sync` preflight, the bridge's balance list, JNI and the Bitcoin routes. | `decode_local_envelope`: the 0x03 frame, canonical re-encoding, v3, no headers, no message id. |
| `dsm_sdk` · bridge/mod.rs · `get_all_balances_strict` | A projection fallback injected zero ERA and dBTC rows. | The router's `balance.list`, decoded as a local answer; its errors are errors. |
| `dsm_sdk` · handlers/app_router_impl.rs | Router init ran `let _ = core.initialize_with_genesis_state()` (a zero-entropy synthetic genesis head); `wallet.send` marked a relationship `RESYNC_REQUIRED` whenever a second send preceded the first step's finality, and read errors defaulted. | The router refuses without a head ("install the wallet's genesis before AppRouter init"); the head-loss check requires no local head, no pending head and a prior send, read errors fail closed and a failed mark is an error. Test: `a_send_before_the_previous_step_finalizes_is_gated_never_marked_for_resync`. |
| `dsm_sdk` · sdk/core_sdk.rs | `sign_raw`/`sign_operation` (a BLAKE3 digest presented as a signature), `initialize_with_genesis_state`, `apply_incoming_transfer_full_state` (apply without acceptance artifacts), `remote_signed_pair`, `query_state_range` (fabricated proof and root), `verify_and_add_contact`/`verify_genesis`/`extract_public_key_from_genesis`, `generate_policy_verification_proof`, `validate_token_policy`, `list_contacts` (fabricated fields), twelve "not available in CoreSDK" refusals, `create_genesis_with_passive_contributors`, `device_tree_root_or_genesis` (zero-root fallback), `set_device_head_for_testing`, the `cfg(test)` mock chip in `hardware_appliance_or_fail`, `commit_advance_with_pending_admission` (a zero storage-set id; no callers). | Deleted. |
| `dsm_sdk` · anchor/appliance_client.rs | `InProcessAnchorAppliance`, an in-process TROPIC01 mock (Ed25519, SMT leaf verification mocked true) and a `recover` default returning `DowngradeOnline`, in shipped code. | Deleted; the interface remains, `ed25519-dalek` is gone from the SDK. |
| `dsm_sdk` · handlers/faucet_routes.rs | `faucet.check_nearby` answered "available" unconditionally and ignored its device id (no caller); `faucet.claim` checked the request's device id for length and then ignored it. | `faucet.check_nearby` deleted. `faucet.claim` claims only for the device that makes it. Test: `the_claim_route_claims_only_for_the_device_that_makes_it` (check removed → red); no test drove the route before. |
| `dsm_sdk` · handlers/token_routes.rs · `token.create` | The threshold was `clamp(1, 255)`: a request of 0 became 1. | Refused outside 1..=255. Test: `a_threshold_the_policy_cannot_hold_is_refused` (clamp restored → red). |
| `dsm` · `testing` feature | `ValidatedPeerTransition::single_root_for_test` and `resolved_sofi_for_test` assembled peer transitions without the walk; `reset_bridge_handlers_for_tests`, `generate_for_testing` and the `DeviceState` fixture advances were real methods for any crate enabling the feature (the SDK did, through a dev-dependency). | The feature is deleted with its self dev-dependency and the SDK's; the `DeviceState` fixture advances are `cfg(test)`. Deleted with them: `dsm/tests/economic_peer_debit_lineage.rs` and five tests of `dsm/tests/economic_peer_evidence.rs` (listed under Open). `ci/peer_debit_lineage_authoritative.sh` now requires that nothing constructs `ResolvedSofi`, that no `_for_test` constructor exists and that nothing is gated on a `testing` feature. |
| `dsm_sdk` · unused features and dead code | Features `mock-anchor` (an in-process mock secure element whose receiver auto-admits a deterministic identity), `test-mock`, `local-mpc` ("dummy participants + dummy entropy"), `deny_fallback`, `examples`, `diagnostics`, `perf-metrics`, `storage`; `mock_anchor_seed`; `sdk/android_storage_demo.rs` (not compiled); `sdk/dlv_sdk.rs` (no callers); `online_chain_tip_from_sdk_context_b32` and its test seam; `RecoverySDK` and `lib.rs` wallet-seed setters for tests; `signing_authority` test key setters. | Deleted. |
| `dsm_sdk` · tests/ and examples/ | Integration tests that built fabricated identities and records (`genesis_wallet_persistence`, `mixed_protocol_test`, `inbox_genesis_mismatch`, `canonical_bilateral_schema_tests`, `transaction_display_amount`, `token_resolution`, `policy_rehydration`), tested removed models (`token_mint_burn_routes`, `token_decimal_scaling`, `token_create_*`, `token_registry_persistence`, `faucet_claim`), were ignored or live-only (`live_e2e`, `b0x_integration`, `bilateral_event_guarantee`, `e2e_*`, `head_byte_budget_probe`) or passed by skipping (`legacy_device_head_decode`); all five examples (two built on the deleted default-device `CoreSDK::new`, one defaulting to a fixed recipient, one simulating a BLE peer, one printing an encoding). | Deleted. The properties still true are lib tests: `token_create_tests` (fee atomicity, a repeat answered from canonical state, a taken ticker refused, scaling to base units once, overflow, threshold, amounts at the token's decimals, a created token sent after its creator restarts), `an_unknown_path_is_refused_by_name_on_both_halves_of_the_router`, `rendering_is_exact_at_the_awkward_magnitudes`. |
| `dsm_sdk` · handlers/bitcoin_invoke_routes.rs tests | Once the tests' identity became a real device, two looked their withdrawals up under the old fixed device id `[0xA1; 32]`. | The router's device id. No Bitcoin code changed. |

**Open**

| Location | Finding |
|---|---|
| `dsm` · economic/provenance.rs · P15-9 | Nothing constructs `ValidatedPeerTransition::ResolvedSofi`, so the refusal in `prevalidate_sender_debit` has no input that reaches it and no test that attempts the debit. The peer walk refuses every conditional claim (E1c-3); whether a trader whose lineage holds a SoFi position can pay anyone afterwards is not exercised. |
| `dsm` · economic/provenance.rs · `verify_credit_source` | The refusal clauses a burn funds nothing, a transfer to a third identity, a debit that is not the operation's debit, an acceptance that cannot be fetched and acceptance bytes that do not hash to their address lost their tests with the fabricated transitions; they need a transition from a real walk. |
| `dsm_sdk` · handlers/bilateral_impl.rs · `BiImpl` (offline boundary) | `prepare` on a non-Android build returns success with a commitment over any bytes, an empty signature and defaulted keys; `accept`, `commit` and `transfer` validate and then refuse as "disabled". Reached through `dsm::core::bridge` universal ops; `tests/bilateral_sdk_integration_tests.rs` pins the behaviour. Recorded, not rebuilt: offline is a dependency boundary this round. |
| `dsm` · core/bridge.rs · `envelope_error` | Derives device, chain-tip and genesis header hashes from the error text (see §6.8, `Headers`). The zero `post_state_hash` of `op_error`/`op_success` is resolved in §6.8. |
| `dsm_sdk` · handlers/wallet_routes.rs · `decimals_for_token`, `merge_balance_projections` | A registry read error or an unknown token renders at 0 decimals; projection rows override the head's balances in `balance.list`, so the displayed balance is not the canonical one. |
| `dsm_sdk` · handlers/token_routes.rs | Projection writes after an admitted advance read the locked amount as `unwrap_or(0)` and only log a failure. |
| `dsm_sdk` · handlers/core_bridge_adapters.rs | Four tests are `#[ignore]`d as flaky under parallel execution; the board runs serially. |
| `dsm_sdk` · storage/client_db/projection_repair.rs · `tip_reconcile_converges_from_finalized_proposal_evidence` | Inserts a contact and a finalized proposal with made-up hashes (its dropped time columns are gone from the insert; the hashes are not derived). |
| `dsm_sdk` · tests/balance_wire_fixture.rs | The frontend wire fixture carries a made-up anchor and a canonical token id that is not derived from it. |
| `dsm_sdk` · sdk/core_sdk.rs, sdk/token_sdk.rs | `execute_transition` and `execute_on_relationship` (advances without admission, a legacy `State` view) remain; Core declares `TAG_DSM_TEST_ENTROPY`. |
| `dsm_storage_node` · db/pg.rs · `init_db` | Migrates a legacy `inbox_spool` (adds `seq_num`, drops `acked`/`expires_at_iter`); beta takes clean cuts. |
| `dsm_sdk` SoFi unit tests (deleted: fabricated constants, a fake fleet and fake registers) | Owed on real vaults: `sofi_advance` 7 (relay completion, the next trade's vault head, rebuilding a consumed generation, a vault record that cannot reproduce its root, a precommit naming another parent claim), `sofi_evidence` 10 (nothing defaulted, withheld objects unavailable, non-authenticating bytes never acquired, a wrong policy refused by Core, local leaves recomputing the root), `sofi_exercise` 3, `sofi_publish` 5, `sofi_register` 11 (both halves at the leader, waiting on conformance, a racing ordinary claim, attempts above zero), `sofi_resolve` 4, `sofi_chain` 4. |
| `dsm_sdk` · recipient and bilateral tests (deleted: fabricated journals, records and holds) | Owed with a real fault between the accept transaction and convergence: a conflicting apply never accepts, a failing apply stays retryable, a prepared journal advances nothing, convergence rejects a mismatched record, a relationship-finalized certificate with substituted fields (A's step key is erased after signing), crossing sends (R12). |
| offline-bearer producer | The mock chip is gone and no appliance transport exists, so no offline-bearer producer path runs; its tests were deleted with the mock. Dependency boundary this round. |

### 6.8 The clock pass (branch `fix/beta-skeleton-compile`, 2026-09-24)

The deterministic clock (`dsm::utils::deterministic_time`, the SDK's `util::deterministic_time`, `utils::time`, `utils::timeout`) is deleted: nothing advanced it, so every reader got 0 or a constant. Each consumer now has the order it actually has (a SQLite rowid, a chain position, the content of what it names) or the concept is gone. Client schema v18 carries no time and no counters. Wire fields whose only value was the clock are reserved.

**Resolved**

| Location | Finding | State |
|---|---|---|
| `dsm_sdk` · storage/client_db · schema | Time-keyed indexes, every `ALTER TABLE` migration (`ensure_*`, `replace_transactions_schema_without_unix_ts`, the v1→v2 `anchor_enrollments` rebuild) and the `genesis_records` column adds ran beside the schema-version gate; two re-added dropped time columns. `transactions.chain_height`/`step_index` were `NOT NULL` though nothing wrote them, so every history insert failed. | The version gate is the only compatibility mechanism; `contacts` declares `device_tree_root` itself; the two counter columns are gone. Tests: the `transactions` settlement suites (red on the stale DDL). |
| `dsm_sdk` · storage/client_db/system_peers.rs, types.rs | `SystemPeerType::from_str` mapped any string to `Protocol`; row decoders defaulted an unknown type and an undecodable metadata blob. | Exact inverse of `as_str`; a corrupt row is an error. Tests: `system_peer_type_parse_inverts_as_str`, `system_peer_type_parse_refuses_any_other_spelling`. |
| `dsm_sdk` · storage/client_db/ble_chunk_buffer.rs | Keep-50 eviction ordered frames by a creation tick that never moved, so it evicted arbitrary frames. | Ordered by each frame's newest chunk (rowid). Test: `cleanup_orphan_chunk_buffers_evicts_the_least_recently_persisted_frames`. |
| `dsm_sdk` · storage/client_db/bitcoin_accounts.rs | The XChaCha20-Poly1305 nonce was `BLAKE3(account_id ‖ tick)`: under the frozen tick every re-encryption of an account's secret reused one nonce under one key. | Synthetic nonce keyed by the encryption key and bound to the plaintext. Test: `synthetic_nonce_never_repeats_across_distinct_secrets`. |
| `dsm_sdk` · storage/bilateral.rs (`BilateralStorageSDK`) | A second SQLite store (`bilateral_chains.db`) no production path wrote: empty counterparty and commitment, phase `"unknown"`, a process-local `created_at` counter restarting at 1 under `(counterparty, created_at)` primary keys. `BiImpl::get_pending_transactions` read it, so the JNI `getPendingBilateralProposalsStrict` (no Kotlin caller) could only answer empty. | Deleted with the router field, the handler method, `get_pending_bilateral_proposals_strict` and the JNI export. The pending list is `bilateral.pending_list` over `bilateral_sessions`. |
| `dsm_sdk` · storage/client_db/bilateral_sessions.rs · `cleanup_expired_bilateral_sessions` | `Ok(0)` unconditionally; no caller. | Deleted. |
| `dsm_sdk` · bluetooth/bilateral_envelope.rs · `build_envelope` | With no tip override the header chain tip was `H(genesis ‖ tick)`, and the message id `H(device, genesis, tip, tick)`: two envelopes at one tip shared an id. | The reserved header value the proto defines; the message id is BLAKE3 over the envelope encoded with an empty id. Test: `build_envelope_message_id_is_content_addressed`. |
| `dsm_sdk` · bluetooth/bilateral_ble_handler.rs · `register_sender_session` | Its doc named a JNI caller that does not exist; it ignored the commitment hash its caller passed. | Deleted with its test. |
| `dsm` · core/bridge.rs · `handle_bilateral_offline_send` | Only its own tests called it; without a handler it answered with a "lightweight" commitment binding zero bytes for absent hashes. | Deleted with its four tests. |
| `dsm_sdk` · sdk/runtime_config.rs, sdk/storage_node_health.rs, sdk/discovery.rs, sdk/network_detection.rs, network.rs quarantine | `RuntimeConfig` minted a device id from hostname, a counter and the tick and a "device entropy" from a fingerprint and the tick; the health monitor reported `response_time_ticks = 4` for every healthy node; the `dev-discovery` feature (mDNS) was a development mode; the registry's round robin and tick quarantine had no caller. | Deleted, with the `dev-discovery` and `mdns` features and the `dirs`, `hostname` and `mdns-sd` dependencies; `RuntimeConfig` keeps only `get_bitcoin_network`. |
| `dsm_sdk` · sdk/wallet_sdk.rs | `locked` gated 22 methods; only the never-firing tick auto-lock set it in production, and `unlock(_password)` ignored the password. | The flag, `lock`, `unlock`, the activity clock and `auto_lock_timeout` are deleted. |
| `dsm_sdk` · sdk/b0x_sdk.rs | The circuit breaker's recovery window never elapsed under the frozen tick; `B0xEntry.tick` was `H(tip)` read as a time; `request_timeout`/`retry_delay` were never read; the online-message nonce zero-filled a short id or tip. | A failed member stays failed until a success, and is still asked last; the fields are gone; a short id or tip is refused. |
| `dsm_sdk` · jni · `nowTick`, `JniResult` (twice) | No Kotlin caller; the result types were unused. | Deleted (Rust, `Unified.kt`, `UnifiedNativeApi.kt`). |
| wire · `proto/dsm_app.proto` | Fields whose only value was the clock or a counter DSM does not keep: `BilateralPrepareRequest.validity_iterations`, `BilateralPrepareResponse.expires_iterations`, `TransactionInfo.logical_index` and `created_at`, `FaucetClaimResponse.next_available_index`, `ContactAddResponse.verify_counter` and `added_counter`, `InboxItem.tick`, `OnlineTransferRequest.seq`, `OnlineMessageRequest.seq`. | Reserved by number and name. `seq` also left the §4.1 transfer nonce and the online-message signing and nonce preimages; `generate_online_transfer_nonce` (its one caller's nonce was discarded) and `compute_transfer_signing_bytes_v3` (no caller) are deleted with their domain tags. Frontend protos regenerated; the frontend stops sending and reading every one of them, and no longer renders transaction times, contact counters, a faucet cooldown or a mint control. |
| `dsm` · sofi/leader.rs | `successor_cell_leader` lost its production caller when cells became routed; a route's position 0 is the same function. | Deleted. Its properties hold on the route: `an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s`, `an_attempt_cells_leader_is_bound_to_the_vault_and_the_parent_root`; a subset of `S` is refused by `a_cell_is_routed_only_over_the_committed_set`. |
| `ci/sofi_genesis_acceptance_binding.sh` | The gate failed on any `genesis_accepted` in Rust; the specification corpus (SoFi §19.8, §28 step 5) names it, binding the genesis to the accepted owner transition. | The gate now requires that form: one `genesis_accepted`, whose owner is the walk's `ValidatedPeerTransition` (constructed only by `validate_peer_lineage`) and which takes no operation or creation of its own. Mutation controls: a `ValidatedEconomicRoot` owner and an added presented `Operation` each fail the gate. |
| `ci/admitted_predecessor_readers_fenced.sh` | `sofi_evidence.rs` reads admitted history and was unclassified. | Exempt with its reason: it gathers the claim accepted at a setup's position for SetupValid and creates no position. |
| `tools/vertical_validation` | Did not compile against Core (removed constructor arities, contact fields and `update_contact_chain_tip_unilateral`). | Compiles; the replay's contact tip carries a real inclusion proof under the relationship key (it used an empty tree and a zero key). |
| `dsm_sdk` · sdk/recovery_sdk.rs · `derive_recovery_rollup` (recovery boundary) | Read `chain_height` from the history table, a column nothing wrote meaningfully. | `ht'_i` is derived from the history: the number of the peer's receipts accepted up to and including this one. Test: `the_rollup_derives_each_peers_height_from_the_history`. |
| `dsm_sdk` · storage/client_db/bcr.rs · `get_bcr_chain_states`, `get_bcr_chain_states_for_rel` | Skipped a corrupt row (undecodable bytes, a state that does not recompute its stored tip) with a warning; only the supply-cap derivation asked a thread-local dropped-row counter, so policy resolution, token metadata lookup and recovery segments read a history with rows missing as complete. | A corrupt row fails the load, for every caller; the counter is deleted. Test: `a_corrupt_archived_row_fails_the_load` (tip check disabled → red). |
| `dsm` · core/bridge.rs `op_error`/`op_success`; `dsm_sdk` · init.rs, jni, b0x_sdk.rs | `OpResult.post_state_hash` and `ResultPack`/`ArgPack.schema_hash` were 32 zero bytes wherever no state or schema exists, including on the b0x wire. | Absent (both fields are optional messages); the frontend's contact add sends no schema hash either. |

**Open**

| Location | Finding |
|---|---|
| `proto/dsm_app.proto` · `Headers.chain_tip`, `Headers.seq` | Documented "RESERVED/IGNORED, SDK emits zeros", yet the Core envelope parser requires a 32-byte `chain_tip` and b0x reads it as the route tip. Local answer builders (`ingress.rs`, `jni/helpers.rs`, iOS `create_error_envelope`) zero or hash-fabricate `device_id`, `genesis_hash` and `message_id`. The contract needs one meaning: reserved everywhere, or defined. |
| `dsm_sdk` · handlers/app_router_impl.rs, sdk/b0x_sdk.rs · `balance_anchor` | `Balance::from_state(amount, H(DSM/balance-anchor, []))` — one constant anchor — in the signed transfer operation, on both sides. |
| `dsm_sdk` · handlers/app_router_impl.rs · `wallet.send` | Runs through WalletSDK's in-memory device book (an entry with an empty public key and alias `online-…`), an in-memory chain-tip map beside `contacts`, and a wallet-level signature "for record keeping". |
| `dsm_sdk` · sdk/core_sdk.rs, sdk/token_sdk.rs · `token_metadata_from_proto` | Two converters; one defaults an undecodable owner to zero bytes, an unknown type to `Created`, and clamps decimals. |
| `proto/dsm_app.proto` · `TokenPolicyCacheEntry.max_supply`; `TokenCreateRequest.threshold` | The cache entry's `max_supply` carries the genesis supply; the create request's threshold is client-supplied though the signer set is Rust's (one signer, so only 1 is valid). |
| `dsm_sdk` · storage/client_db | Poisoned-lock recovery (`unwrap_or_else(|p| p.into_inner())`) continues on whatever a panicking writer left. |
| `dsm_sdk` · `test-utils` feature | Enabled by the crate's own dev-dependency; gates at least `reset_database_for_tests`. Inventory owed. |
| `dsm_sdk` · sdk/b0x_sdk.rs · message ids | Submissions without a durable identity use a random id, so a retry spools a second row. |
| `dsm_storage_node` · replication.rs, api/transport/gossip.rs, api/registry/discovery.rs | Gossip, replication and discovery carry ticks (`StorageNodeInfoV1.last_seen_tick`, `GossipMessageV1.sender_tick`, `AdminMaintenanceResponseV1.tick`). MR-DSM-0055 allows logical ticks for ordering inside a node; the storage-node sweep checks that these are logical, advance, and reach nothing protocol-relevant, and that gossip exists in the storage spec at all. |
| frontend | Talks to storage nodes directly (`storageNodeService.getObject`, `objectBrowserService`, `E2E.storage.integration`), a layer skip; `DiagnosticsBundle.tick: 0` and `PendingBilateralRecord.tick: idx + 1` are fabricated; `useTransactions` defaults type and status. Frontend sweep. |
| `dsm` · sofi/exercise.rs, sofi/registration.rs, economic/register.rs, economic/native_reserve.rs · `check_*_completion` | The completion-proof verifiers (storage §9 rule 9) have no production caller: no party yet receives a kept proof to check. The two under `sofi` are in the G1 baseline with this reason. |
| recovery boundary | `get_latest_capsule_metadata` counts counterparties through unrelated tables with `unwrap_or(0)` under a "for now … proxy" comment; `recovery_sdk` reads the genesis hash with `unwrap_or_default()`. |

### 6.9 The dead-code pass (branch `fix/beta-skeleton-compile`, 2026-09-24)

Every item-level `#[allow(dead_code)]` in `dsm` and `dsm_sdk` (34) and the SDK's crate-level `#![allow(dead_code)]` are removed. Each item the compiler then named was deleted, or its unread field removed; public items the compiler does not flag were checked for callers by hand where a deletion touched them.

**Resolved**

| Location | Finding | State |
|---|---|---|
| `dsm` · core/state_machine/transition.rs · `StateTransition`, `create_transition`, `generate_position_sequence` | Reached only from tests. `finalize` claimed to validate commitment integrity and generate signatures: it hashed into a hasher it discarded, looped over the balances doing nothing, and returned `Ok(())`. `sign_forward_commitment`/`cosign_forward_commitment` stored a signature without verifying it. `to_wire_bytes`/`to_canonical_proto` encoded fields no production path set. | Deleted with their tests. The `mod.rs` chain tests apply the operation directly (they only read `transition.operation`); `tools/vertical_validation` runs the same presence check `create_transition` ran, then `apply_transition`. Wire: `CanonicalStateTransitionProto`, `PreCommitmentProto`, `PositionSequenceProto`, `PositionList` removed from `dsm_app.proto`; the frontend bindings are regenerated. |
| `dsm` · types/state_types.rs | `MerkleProof::verify` compared a 32-byte root with the concatenation path ‖ leaf ‖ root, so it could never succeed; `PositionSequence::verify` compared a seed with a seed the caller supplied; `IdentityAnchor` carried an "MPC threshold ceremony" proof. With `MerkleProofParams`, `SerializableHash` and `SerializableMerkleProof`, none had a caller outside its own tests. `State` and `StateParams` held fields nothing read (`positions`, `position_sequence`, `public_key`, `entity_sig`, `counterparty_sig`; `none_field`, `metadata`, `token_balance`, `signature`, `version`, `forward_link`, `large_state`, `previous_hash`). | Deleted, with tests that only assigned a field and read it back. |
| `dsm` · commitments/precommit.rs, core/state_machine/random_walk.rs | `PreCommitment.data` and `RandomWalkConfig.position_count` were written and never read. | Removed. |
| `dsm` · core/identity, crypto/sphincs.rs, merkle/tree.rs, types/operations.rs, core/contact_manager.rs | No callers: `generate_secure_random`, `select_random_subset`, a key type's `sign`/`verify`, `KyberKey::encapsulate`/`decapsulate`, `sanitize_genesis_state`, `copy_subtree_from`, `get_tree_height`, `dec_option_bytes`, `update_chain_tip_with_proof`. | Deleted. |
| `dsm_sdk` · sdk/wallet_sdk.rs | When `Smaster` could not be derived the wallet installed a random Kyber keypair (a key no counterparty's stored copy matches); `device_id_array` fell back to 32 zero bytes on a malformed id; `get_balance` defaulted the token to `"ROOT"`; `core_sdk` was never read; 13 methods and the lock/auto-lock machinery had no production caller. | The wallet is not built without `Smaster`; the router installs the wallet's Kyber key or fails, instead of warning and sending an empty field. A malformed device id is an error; `get_balance` takes the token it reads. Dead methods and the field deleted. No mutation control: the replaced branch needed a genesis hash without a device id in the app state, which no writer produces (`set_identity_info` writes both), and reaching it would take a test seam. |
| `dsm_sdk` · sdk/token_sdk.rs | 19 methods with no production caller; a recipient id was fabricated by hashing whatever the caller passed when it was not 32 bytes. | Deleted; the recipient id must decode to exactly 32 bytes. |
| `dsm_sdk` · jni | `ensure_bootstrap` (two copies), called by 18 entry points, did nothing but log — its comment said so. `route_query_via_ingress`, `route_invoke_via_ingress(_bytes)`, `error_transport_bytes` (two copies) and `jni_catch_unwind_jlong` had no production caller; their tests ran through `ShimRouter`, a router that answered every query and invoke with fabricated success. | Deleted, with `ShimRouter` and the two tests. |
| `dsm_sdk` · bluetooth/pairing_orchestrator.rs | Off Android, `start_ble_discovery` returned `Ok` without starting anything, and `notify_pairing_complete` did nothing. | Deleted. |
| `dsm` · crypto/rng.rs | `init_with_seed`, public in shipped Core, installed a process-wide seeded ChaCha20 behind `random_bytes` and `SecureRng`: one call made every later draw predictable. Its own test called it, so in the serial lib test binary every later test drew from a stream seeded with 42. `ensure_rng_initialization` probed and set a flag nothing read; `generate_deterministic_random` and `mix_entropy` were called only by tests of themselves. | OS entropy only; the seeded mode, its tests, the two generators and the `DSM/det-rng-seed` domain are gone. |
| `dsm` · core/chain_tip_store.rs · `NoopChainTipStore` | Reported every compare-and-set as applied and kept nothing. `BilateralTransactionManager::new` defaulted to it; every caller of that constructor was a test or the validation tool, so those relationships "persisted" tips that went nowhere. | Deleted; the one constructor takes a store. Core's tests use an in-memory compare-and-set store in a test-only module; the SDK's tests use the SQLite store production uses; the dsm integration test and the tool each carry their own. |
| `dsm` · core/bilateral_transaction_manager.rs · `establish_relationship` | The initial-tip compare-and-set result was discarded: a store holding a tip the contact record did not hold was ignored, and the anchor ran from h_0 (the anchor was also recorded before the write). | Refused, before any anchor is recorded. Test: `establish_relationship_refuses_a_store_tip_the_contact_record_does_not_hold` (refusal ignored → red). |
| `dsm` · core/bilateral_transaction_manager.rs · `BilateralPreCommitment` | `target_state_number = hash[0] + 1`, a fabricated counter, was signed into a SPHINCS+ signature made on every BLE prepare and never transported or verified (the protocol signature is `sign_commitment` over the commitment hash); `verify()` compared the struct's hash with a recomputation from its own fields. | The counter, the signature fields and methods and `verify()` deleted; the trace harness no longer checks them. |
| `dsm` · core/state_machine/transition.rs · `create_next_state` | Took a `verification_type` it ignored; the file's `VerificationType` existed only to be converted and passed in. | Parameter, type and converter removed; `apply_transition` passes what it uses, the transfer mode. |
| `dsm` · core/token · `TokenStateManager`, `TokenRegistry` | No production user. `apply_token_operation` (no caller) applied DLV claims and invalidations as no-ops under a comment that "the caller (DLVManager in Phase 5)" moved the balance; nothing does. | Deleted; the file keeps policy-commit resolution and balance keys. |
| `dsm_sdk` · storage/soft_vault.rs | No user. Shipped a public `TestBindingKeyProvider`; leaked its lock file on any write error; discarded the result of restricting the key file to its owner. | Module deleted, with its five domain tags and `SoftVaultExportV1`. |
| `dsm_sdk` · handlers/app_router_impl.rs · `wallet.send` | The durable `submitting` mark the code relies on for crash safety was written with its result discarded, so a failed mark still sent; the post-call status writes and the reconcile mark discarded their failures; a tuple of five locals was kept alive only to silence them. | No send without the mark (the row stays for the reconciliation sweep); later write failures are reported; the unused locals and artifact fields removed. |
| `dsm_sdk` · sdk/token_sdk.rs, sdk/core_sdk.rs, sdk/wallet_sdk.rs, handlers/token_routes.rs, storage/client_db/projection_repair.rs | A failed locked-balance read became 0 and was written into projections; an undecodable projection source hash became 32 zero bytes (or the current state's hash); a lock the row could not hold was discarded; an empty token id became `ERA`; the "per-purpose" locked read ignored its purpose and fabricated a state hash; `TokenSDK::get_balance` took a state hash it ignored and had no caller. | `balance_from_projection` refuses a bad row; pre-advance reads propagate; post-commit writers leave the row to the repair sweep instead of writing a wrong one; an empty token is refused; the locked read is the token's whole lock and says so. Test: `a_projection_row_without_its_source_state_or_with_an_unholdable_lock_is_no_balance` (zero-hash fallback → red; lock refusal discarded → red). |
| `dsm_sdk` · sdk/receipts.rs, handlers/cert_resync_flow.rs, storage/client_db/sender_outbox.rs, bluetooth/bilateral_ble_handler.rs, sdk/wallet_sdk.rs | Bindings and imports kept only to be silenced (`let _ = x`, `_public_key`). | Removed. |
| `dsm_storage_node` · api/infra/hardening.rs, api/infra/network_config.rs, replication.rs | `QUORUM_Q = 2` ("acceptance quorum") and two thresholds "reserved for future use", with no reader; `validate_config`, `create_dev_node_configs` and `detect_network_config` had no caller; `ReplicationManager.local_address` was never read. | Deleted. |
| `dsm_sdk` · tests/ble_smoke.rs | Three tests built a bilateral manager and never used it. | Removed. |
| `dsm_sdk` · sdk/chain_tip_store.rs · `SqliteChainTipStore` | Mapped every outcome other than an applied write to `Ok(false)`, so an `InvariantViolation` (no contact row, malformed persisted state) read as a lost compare-and-set. | An invariant violation is an error; only a parent mismatch is "not applied". `bilateral_reject_tests` had established a relationship over no persisted contact — possible only under the no-op store — and now persists its contact first. |
| `tools/vertical_validation` · `tla-check` | Exited on the TLC verdicts alone: a literal, direct or linked Rust trace that failed to replay printed `OVERALL VERDICT: FAILURES DETECTED` and exited 0, so CI's "TLA+ model checks" step was green over a failing Tripwire refinement. | The exit follows each spec report's combined verdict, the one the report prints. It now fails on Tripwire (see Open: receipt verifiers). |

**Open**

| Location | Finding |
|---|---|
| `proto/dsm_app.proto` | 83 of 486 messages and enums are named nowhere outside the proto (Rust, TypeScript, Kotlin, Swift, scripts), among them `StateWire`, `TransactionParamsProto`, `SensitiveAppDataProto`, the `Kv*`, `StorageObject*`, `BleTransport*`, `SecureHardware*` and `SdkEvent*` families. Some are reached only as a `oneof` arm whose Rust variant name differs; each needs that check before it is removed. A wire-surface pass of its own, with the vector-corpus check. |
| `ci/sofi_reachability.py` (G1) | Reads each file only up to its first `#[cfg(test)]`. 30 production files have code after a test item (`types/state_types.rs` has its test module mid-file); none under `sofi/` today, so no SoFi definition escapes the gate, but a caller written there is invisible and would let a baseline entry outlive its wiring. |
| frontend | `RecoveryPipelineScreen.tsx` (string concatenation) and `SofiScreen.tsx` (`any`) carry lint warnings from #976. Frontend sweep. |
| `dsm_storage_node` · main.rs, api/infra/admin.rs, api/transport/gossip.rs, api/infra/hardening.rs | A debug-build dev mode: `main.rs` builds `ReplicationManager::new_for_tests` (an unpinned client, replication factor 1) under `cfg!(debug_assertions)`; admin and gossip auth are bypassed by `*_INSECURE_ENV=1` in debug builds; `enforce_release_safety` returns `Ok` in debug; `scripts/dev/start_dev_nodes.sh` drives it. Removing it changes the local-node workflow — owner decision. |
| `dsm_storage_node` · db/pg.rs · `init_db` | Beside `inbox_spool` (§6.7), `cells` gains columns by `ADD COLUMN IF NOT EXISTS` and retired tables are dropped at start-up. A clean cut means wiping the live fleet's databases, which bricks incarnation-pinned nodes unless restored — owner decision. |
| `dsm` · types/state_types.rs, commitments/precommit.rs · `min_state_number` | Forward-commitment types carry a state-number counter DSM does not keep, and it is part of their canonical encodings (a `State`'s hash covers its forward commitment). The bilateral manager's use of it is gone (§6.10); owner ruling #4 removes the rest and regenerates the vector corpus. |
| `dsm` · sofi/wire/objects.rs | Eight `push_bytes` results are discarded on the ground that construction bounds the lengths; the honest form makes those five encoders fallible. |
| `dsm_sdk` · sdk/core_sdk.rs · `apply_incoming_transfer_staged` | A losing racer is told apart from other failures by substrings of the error message. |
| `dsm` · types/state_types.rs · `State::new_genesis` | Flags a genesis state `Recovered`. |
| discarded results (`let _ =`) | After this pass: the offline BLE transport, pairing and `wallet.sendOffline` (dependency boundary), Bitcoin (not touched), the recovery routes (boundary), platform sinks with no host counterpart (the WebView event push, `device.requestAdmission`, the localhost policy), channel sends to receivers that may have gone, and once-cell installs. |

### 6.10 Rulings applied and the legacy transition layer removed (branch `fix/beta-skeleton-compile`, 2026-09-24)

Owner rulings of 2026-09-24 (receipts, `wallet.send`, the rule that nothing which does not contribute to the acceptance predicate may pose as authenticated state), the second false-success audit (R01–R06), relayed findings, and the removal of the `State` transition layer that production never ran.

**Resolved**

| Location | Finding | State |
|---|---|---|
| receipts · `dsm` merkle/sparse_merkle_tree.rs, verification/receipt_verification.rs, types/receipt_types.rs; `dsm_sdk` sdk/receipts.rs | Two verifiers that could not check the same receipt; field 11 carried a constant stub; field 9 a second encoding of the path. | One path, one primitive: `verify_smt_replace(pre_root, key, old_leaf, new_leaf, siblings)` folds the parent path with the old leaf to the pre-state root and returns the fold with the new leaf. `verify_receipt_state` is the one set of state rules (sender before signing, recipient before accepting, `verify_stitched_receipt` rules 3–4). Fields 9 and 11 reserved. The SDK builder takes the real tree path and a real Device Tree proof, with no fallback; the SDK's second verifier, its proof (de)serializers and the witness modules are deleted. Test: `the_state_rules_hold_only_for_what_the_one_path_proves` (each mutated field refused; two mutations red). |
| `dsm` · verification/receipt_verification.rs · `verify_stitched_receipt` | Ignored the context's expected parent root, and the context carried a consumed-parent set nothing read. | Rule 2c refuses a receipt over any other root; the unread set is removed (the tracker is the uniqueness rule). Test: `a_receipt_over_a_root_the_verifier_does_not_expect_is_refused` (rule removed → red); a refused receipt consumes no parent. |
| `dsm` · types/receipt_types.rs · `print_test_vector_hash_for_spec` | A test with an empty body. | Deleted. |
| `dsm_sdk` · `wallet.send`, `sendSmart` | An empty token id meant ERA; tickers were case-folded at the router. | Refused; the token is named exactly (ruling #5). Test: `a_transfer_naming_no_token_or_a_misspelled_one_is_refused_and_nothing_moves` (mutation red). |
| `dsm` · types/policy_types.rs, core/token/policy (R01) | `PolicyCondition::VaultEnforcement` decoded and was enforced against a context no production path built. | The variant, `VaultCondition`, the enforcement context and the `rate_limit` witness removed; the wire field reserved. Test: `a_policy_carrying_a_vault_condition_does_not_decode` (lenient decode → red). |
| `dsm_sdk` · storage/client_db/native_reserve.rs · `release_at` (R03) | A negative stored supply read as zero; generation 0 underflowed. | Errors. Test: `a_corrupt_memo_row_is_an_error_not_a_release` (mutation red). |
| `dsm_sdk` · sdk/token_sdk.rs · `token_exists` (R04) | An unreadable archive read as "no such token". | Propagated. Test: `a_token_lookup_over_an_unreadable_archive_is_an_error_not_absence` (mutation red). |
| `dsm_sdk` · jni/unified_protobuf_bridge.rs (R05) | BLE events other than identity were dropped with success. | Routed to the Android bridge, or `NotReady` without one; an event with no payload is `InvalidInput`. Verified by the Android build only; there is no host harness. |
| `dsm_sdk` · sdk/storage_node_sdk.rs (R06) | A malformed `custom_ca_certs` entry was skipped. | A missing key is none; any other type is an error. Test: `custom_ca_certs_is_a_list_of_readable_paths_or_an_error` (mutation red). |
| `dsm_sdk` · sdk/dlv_pre_commitment_sdk.rs | A public verifier that accepted no signatures, and a hash that did not separate parameter sets. | Module deleted (no production caller). |
| `dsm_sdk` · handlers/token_routes.rs · `token.forget`; sdk/core_sdk.rs · `execute` | A missing device head read as a zero balance; the policy check ran over a zero state hash when no head was loaded. | Both refuse. The router is built only over a head and a head is never cleared, so neither branch is reachable on a live router and no test can build it. |
| `dsm` · types/operations.rs, types/general.rs | `Ops::validate` passed every variant but three; `Ops::execute` executed nothing; `GenericOps`, and every type in `types::general` (`KeyPair`, `IdToken`, `DirectoryEntry`, `Commitment`, `VerificationResult`, `SecurityLevel`), had no user. | Deleted. |
| `dsm_sdk` · contacts `Bricked` | Three send/prepare gates and a send-status arm read a status nothing ever wrote (`brick_contact` had no caller since the initial commit). Tripwire (§53) is enforced by the relationship-leaf compare-and-set. | Removed (owner, 2026-09-24). |
| `dsm` · core/state_machine/transition.rs, relationship.rs, bilateral.rs | The `State` transition layer (`create_next_state`, `apply_transition`, `enforce_operation_authorization` — a presence check — `verify_transition_integrity`, `verify_token_balance_consistency`, the burn and DLV signature checks, `RelationshipManager`, `BilateralStateManager`) had no production caller: production advances through `DeviceState::advance`. R02's owner-key check lived here. | Deleted. The one signing rule is `Operation::signing_bytes`. Production burns are authorized by the policy's `TokenAuthority` condition over `token_authorization_preimage`; `TokenSDK` burns, which signed a preimage only the deleted path read, now carry the same witness as `token.burn` (`signing_authority::token_authorization_witness`, shared with `token.create`). |
| `dsm` · core/bilateral_transaction_manager.rs | Precommitments were hashed over per-pair bootstrap `State`s that nothing advanced, carrying `min_state_number`; `verify_relationship_integrity` recomputed `mutual_anchor_hash` from the same struct's fields; `commit_bilateral_smt_update` and `update_anchor_from_replace*` had no production caller (the trace committed through them over a fresh empty tree); `tx_hash`, `BilateralTransactionResult`, `is_synchronized` and the anchor's `smt_proof` had no reader. | A precommitment is `H(DSM/bilateral-session; lp(h_n) ‖ lp(op))` with its `parent_tip`; the rest deleted; `remove_pending_commitment` folded into `consume_pre_commitment`. |
| `dsm` · core/contact_manager.rs, types/contact_types.rs; `proto` · `ContactAddResponse` | `LocalSmtVerifier` cached genesis material nothing read and proved chain tips over trees that were never the device's; every production contact carried `chain_tip_smt_proof: None` and an empty `genesis_material`. | Verifier, fields and proof type removed; field 5 reserved; the frontend's never-rendered "SMT proof" row removed. |
| `dsm`, `dsm_sdk` · h_0 | Three copies of the relationship's initial tip. | One public `initial_relationship_chain_tip`. |
| `dsm` · types/device_state.rs · `DeviceState::advance`, a relationship's first step | The first advance wrote `h_0` into the relationship leaf and replaced it in one step, so the step's pre-state root was the root of a tree the device never committed; a verifier holding the sender's committed root refused every first-contact receipt, and the root chain broke across relationships (§12). An SDK test asserted the two roots differ. | Owner, 2026-09-24: a relationship is established before its first step. `DeviceState::establish_relationship` commits its leaf at the `h_0` Core derives, as a root advance that moves no value; a device's own relationship is established at its creation; `advance` refuses a relationship not established and no longer takes an initial tip. The SDK establishes on `contacts.add` (also for a contact an earlier attempt did not establish), persisting the head before installing it; canonical rebuild establishes before a relationship's first preserved state. Tests: `a_relationship_steps_only_from_a_leaf_the_device_committed` (fallback seeding restored → red); `a_first_step_receipt_starts_from_the_root_the_device_committed`. |
| `dsm` · merkle/sparse_merkle_tree.rs · `update_leaf` | Returned `Result` and could not fail; 35 callers carried error paths that could not run. | Infallible. |
| `dsm_sdk` · bluetooth/bilateral_ble_handler.rs · `remove_pending_commitment` | Duplicated `consume_pre_commitment`; its callers discarded the result with `let _ =`. | Folded into `consume_pre_commitment`, which returns what it removed. |
| `tools/vertical_validation` | Traces, properties, adversarial attacks and the throughput benchmark ran the deleted layer through `compat_shim`. The DSM trace replay copied the model's next state — `deviceBalance` among it — into the harness for several actions, so those projections compared the model with itself. Adversarial "balance underflow" tested `u64::checked_sub`; "replay" passed when the replay was accepted. The offline-finality and non-interference traces claimed conservation on the struct self-comparison. `adversarial` and `crypto-kat` exited 0 on failure. | Rebuilt on `live_device`: real `DeviceState` heads, SPHINCS+-signed operations, receipts from the sender's advance judged by Core's verifier with a parent tracker. Deliveries in the DSM replay run the real step; the model's balances are projected from real heads through a stated abstraction function; an action the replay does not implement is a named failure, not a copy. Conservation is checked across two heads. Both commands exit non-zero on failure. |

**Open**

| Location | Finding |
|---|---|
| receipt verification on the live path | `verify_stitched_receipt` has no production caller; production checks the state rules with `verify_receipt_state` (the BLE confirm converged onto it, §6.11). |
| DLV operations | `DlvCreate`/`DlvUnlock`/`DlvClaim`/`DlvInvalidate` signatures were verified only in the deleted `create_next_state`; their executor is `BitcoinTapSdk` (dBTC deferred). No live verification. |
| `dsm` · types/state_types.rs · `State` | A compatibility view synthesized from the head, still read in production (token and wallet SDKs, and the Bitcoin routes, which store `State` in structs and read its `hash` and `token_balances`). Removing it touches Bitcoin code. |
| `dsm` · core/bilateral_transaction_manager.rs · `initial_chain_tip_from_device_ids` | Self-loop relationships derive `h_0` with 32 zero bytes where each genesis goes. |
| two `h_0` formulas | A device relationship leaf starts at `initial_chain_tip_from_device_ids` (the device ids with 32 zero bytes where each genesis goes), the value the online paths and the receiver's A-side pin use; the bilateral manager, the contact record and the BLE symmetric tip use `initial_relationship_chain_tip` (both geneses). One relationship has two `h_0`. |
| `dsm_sdk` · bridge/mod.rs · `AppRouter` | Default trait methods answer "not implemented on this router"; the pre-identity router relies on them. A router without a head cannot advance, and the refusal should say that. |
| `tools/vertical_validation` · DSM replay | Vault and emission actions (`create_vault`, `unlock_vault`, `consume_jap_and_emit`, `consume_spent_proof`, `select_winner`) and the offline actions have no Rust transition in the replay; a trace that reaches one fails on it by name. Harness balances enter by faucet-claim advances without the admission that precedes them in production. |

### 6.11 One receipt on the BLE confirm, headers that name only the sender, no forward commitment, no signed balance anchor (branch `fix/beta-skeleton-compile`, 2026-09-24)

Owner rulings #4 (remove `min_state_number`), #6 (a field no receiver verifies does not stay on the wire) and #7 (remove `Balance.state_hash` from the signed canonical representation), and the ruling of 2026-09-24 on local answers (a response this device's Core or SDK gives its own caller makes no sender claim and carries no headers).

**Resolved**

| Location | Finding | State |
|---|---|---|
| `dsm_sdk` · bluetooth/bilateral_ble_handler.rs · `handle_confirm_request`; `proto` · `BilateralConfirmRequest` | The receiver checked the sender's parent and child paths separately against roots the confirm carried beside the receipt (fields 3, 4, 5, 9), never bound those roots to the receipt, and fed the unbound roots to the offline-bearer predicate with a zero fallback. | The receiver decodes the receipt once, refuses one not from this session's sender to this device, and runs `verify_receipt_state` against the Device Tree root it keeps for the sender; the bearer predicate takes its roots from that receipt. Fields 3, 4, 5, 9 reserved. Test: `a_confirm_whose_receipt_does_not_hold_is_refused_before_the_ek_check` (the state-rule call removed → red; the device binding removed → red). |
| `dsm_sdk` · bluetooth/bilateral_ble_handler.rs · confirm and commit | Zero stood in for a missing receiver challenge, root, parent tip and policy id; an unresolved receiver policy commit became empty deltas left for the conservation guard to refuse; unreadable cert-chain heads, anchor frontiers and contact Device Tree roots read as absent (an unreadable frontier meant "first transfer, adopt the release's root"); the sender's commit, lacking a signed receipt, archived one rebuilt without signatures. | Each is a refusal or an error naming what is missing. The sender refuses to commit without the receiver's counter-signed receipt; it checks that receipt's state rules against the Device Tree root it keeps for the receiver. |
| `dsm_sdk` · sdk/receipts.rs · `build_bilateral_receipt_with_smt`; storage/client_db/contacts.rs · `get_contact_device_tree_root` | The builder returned `None` with the reason only logged; the Device Tree root read turned a closed database, a malformed id and a corrupt blob into "no root". The local Device Tree commitment was derived from the device id when the app state held none. | `Result` on both; the local commitment comes from the app state or is an error. |
| `proto` · `Headers.chain_tip` (2), `Headers.seq` (4) | The tip was zero from the SDK, the relationship's tip on the b0x path, and a hash of an error string from the Core bridge; the one reader, the previous-tip route filter, compared it with the held tip. `seq` counted nothing a receiver read. | Reserved; the parser refuses both tags and requires `genesis_hash`. The inbox address hashes the relationship's tip (storage node spec §8), so a previous-tip route item is non-adjacent by its route: never applied, consumed when already accepted. The SDK's header counter is removed. Tests: `strict_decode_refuses_the_reserved_header_tags`, `strict_decode_requires_the_genesis_hash` (each gate removed → red). |
| `proto` · `Invoke.pre_state_hash` (4), `Invoke.post_state_hash` (5); `OnlineTransferRequest.chain_tip` (8) | Written as zeros, or read into a `B0xEntry` field nothing read. | Reserved; `B0xEntry.sender_chain_tip`/`next_chain_tip` and `B0xSubmissionParams.next_chain_tip` removed; `wallet.sendSmart` no longer resolves a tip only that field carried. |
| `dsm` · commitments/precommit.rs, types/state_types.rs (ruling #4) | `ForwardLinkedCommitment` (its signer id hard-coded to `"entity"`), `EmbeddedCommitment`, `PreCommitment.forward_commitment`, `State.forward_commitment` / `StateParams::with_forward_commitment` and the state-types `PreCommitment` carrying `min_state_number` — nothing in production set any of them, yet `State::to_bytes` encoded the absent commitment. `encode_forward_commitment_params`, `generate_forward_commitment_verification` and the `ForwardCommitment` error variants had no producer. | Deleted with their hash domain; the recovery `carry_forward_commitment` is a different concept and stays. |
| `dsm` · types/token_types.rs, types/operations.rs (ruling #7) | Every operation amount signed a 32-byte state hash: `wallet.send`, the inbox decoder and the BLE hint path stamped `H(DSM/balance-anchor, ε)`, a constant naming no state; other paths a zero hash; `Balance::zero()` stamped a fallback hash from a thread-local context nothing set. | An operation signs an amount as value and lock (`Balance::canonical_amount_bytes`, 16 bytes) and decodes exactly that; operations are built with `Balance::amount`, which references no state. A held balance still records the state it was derived from (`balance_from_projection`). The anchor, the thread-local context and both hash domains removed. Tests: `an_amounts_state_reference_is_not_signed` (encoding restored → red), `an_amount_carrying_a_state_reference_does_not_decode` (length check relaxed → red). |
| `frontend` · public/vectors/v1, src/vectors/kv.ts | The v1 corpus #962 deleted everywhere else: no reader, request bytes carrying the removed header tags, cases 0007/0008 driven by `headers.seq` fault injection. | Deleted with its parser. |
| local answers · `dsm` core/bridge.rs; `dsm_sdk` ingress.rs, jni/helpers.rs, jni/unified_protobuf_bridge.rs, platform/ios/transport.rs | Responses to this device's own caller carried invented senders: a device id hashed from the message id or the error text, zero identities, derived message ids; the Core bridge and JNI domain tags existed only for that. `isErrorEnvelope` decoded answers as addressed envelopes, so an app-router answer (already headerless) never read as an error. | One local-answer form (`dsm::envelope::local_answer`, `local_answer_from_canonical_bytes`): no headers, no message id, never sealed, one payload; an addressed envelope and a local answer do not decode as each other. The six tags removed. Test: `a_local_answer_and_an_addressed_envelope_do_not_cross` (the local-answer header refusal removed → red). |

**Open**

| Location | Finding |
|---|---|
| `dsm_sdk` · handlers/app_router_impl.rs · `message.send` | Takes the relationship tip from the caller (`OnlineMessageRequest.chain_tip`) and uses it in the nonce, the signed bytes and the route. No UI or Kotlin caller sends it, and a received online message is classified "not a transfer" and processed by nothing. |
| `dsm_sdk` · sdk/sdk_context.rs · `SdkContext.chain_tip` | A device-global "chain tip" written only by the Bitcoin routes and read by nothing but its own tests. Removing it edits Bitcoin code. |
| `dsm_sdk` · jni/unified_protobuf_bridge.rs · `bilateralOfflineSend` hint path | Builds an online-tier `Transfer` (zero `policy_commit`, no authority policy) that the BLE sender door refuses. Offline is a dependency boundary this round. |
| §5.2 previous-tip route | No executable test drives an item on a previous-tip route through `storage.sync`; the property that a stale parent is never accepted rests on the apply pipeline's tip compare-and-set. |
| `dsm_sdk` · `jni`, `platform/ios` tests | Compiled only for Android or iOS; no build compiles their `#[cfg(test)]` code. |
| `dsm` · common/domain_tags | 93 of 378 declared tags have no user outside the registry; the registry test counts declarations, not uses. |
| `frontend` · src/vectors (`externalCommitV2`, `uiVectors`, `index`) | No importer. |
| `frontend` · `WebViewBridge.framing.test.ts` (`describe.skip`), `bridgeDecoding.integration.test.ts` (`it.skip`) | Skipped tests report nothing (frontend sweep). |

### 6.13 ByteCommit ancestry in route-chain evidence, one write per missing value, no mint after genesis (branch `fix/route-chain-evidence`, 2026-09-24)

Auditor findings on `61d273a3`: the ByteCommit's parent link was not part of the evidence (1), the mirror evidence threshold was unstated (2), `from_leader` rewrote values the leader held (3), and post-genesis mint vocabulary and branches remained (5).

**Resolved**

| Location | Finding | State |
|---|---|---|
| `dsm` · route_chain.rs · `CommittedAt`, `committed_by`, `leader_seen_at` (MR-DSM-0079, MR-STOR-0094) | A ByteCommit backed a link when the record was included under its root; its chain link was never checked, so a ByteCommit with any `parent_digest` counted. | `CommittedAt` carries the member's ByteCommit at the previous cycle (`None` at cycle 1). `chain_link_holds` requires a zero parent digest at cycle 1 and `follows(parent)` after it, and is part of `commits`, the one check both readers use. `dsm_sdk` · sdk/route_seats.rs · `committed_at` fetches the parent from the same mirrors. Test: `route_chain::tests::a_byte_commit_backs_a_link_only_when_it_follows_its_parent` (valid → Final; bent `parent_digest` → `LeaderLinkUncommitted`; orphan at cycle 2 → not Final). Chain-link check removed → red. |
| `dsm_sdk` · sdk/route_seats.rs · `agreed` (storage spec §3, §14 rule 3) | The number of mirrors whose agreement makes a ByteCommit evidence was not stated. | Not a threshold: the storage fault model is crash-only (§3: a node never equivocates or alters what it stores), and a ByteCommit is never accepted by counting mirrors (§14 rule 3). One mirror's copy is taken and the verifier checks its chain link and root. Stated at `agreed`. |
| `dsm_sdk` · sdk/route_seats.rs · `from_leader` (MR-DSM-0083, MR-DSM-0213) | The batch to the leader rewrote every value, including those the leader already held. | Only the values with no link at the leader are written. Test: `a_value_the_leader_already_holds_is_not_written_there_again` (node-backed; the full batch restored → red). |
| `dsm` · core/token/era_token.rs, init.rs; types/error.rs (MR-DSM-0197, MR-SOFI-0307) | `EraTokenManager` minted without limit on testnet and refused on mainnet; `initialize_root_token*`; `DsmError::MintNotAllowed` / `BurnNotAllowed`, constructed only there. No caller outside the module. | Deleted. |
| `dsm` · types/policy_types.rs, core/token/policy/policy_validation.rs, policy_enforcement.rs; `proto` · `SupplyCapProto` (MR-SOFI-0306, SoFi §54) | SupplyCap carried an `unlimited` flag and an unlimited branch, and gated `"mint"`; `TokenAuthority` was documented and reported as mint authority. | Field 2 reserved; `SupplyCap { max_supply }`; validation refuses 0 (§50); enforcement gates `create_token` only; `TokenAuthority` gates burn and creation. Tests: `a_zero_supply_cap_does_not_validate`, `supply_cap_denies_a_creation_that_would_exceed_it`, `supply_cap_gates_only_creation`, `token_authority_gates_only_burn_and_creation`. Zero check removed → red; gate opened to every operation → red; gate closed to creation → red. |
| `dsm` · economic/mod.rs, credit.rs, decode.rs, witness.rs, write_set.rs; `dsm_sdk` · sdk/token_sdk.rs | Documentation named burned classes `0x0023`/`0x0029` as live credit sources, an issuance write-set arm that no longer exists, and a `token.mint` route that does not exist. | Rewritten to the three credit sources (`0x0025`, `0x005D`, `0x005F`) and to no minting after genesis. |

**Open**

| Location | Finding |
|---|---|
| `frontend` · DevPolicyScreen.tsx, AccountsScreen.tsx | User-visible copy still describes a mint/burn authority and a mint/burn role (frontend sweep). |
| `specs/requirements` · status | Requirement status is written by hand; §5A checkboxes and `MASTER_REQUIREMENTS.md` status prose lag the code (auditor finding 4). |

## 7 Totals

| Spec | Rows | Met | Partial | Missing | Violated | Not code | Deferred |
|---|---|---|---|---|---|---|---|
| DSM high-level (MR-DSM) | 272 | 65 | 123 | 28 | 9 | 29 | 18 |
| SoFi (MR-SOFI) | 329 | 217 | 70 | 19 | 6 | 17 | 0 |
| dBTC (MR-DBTC) | 135 | 0 | 0 | 0 | 0 | 0 | 135 |
| Storage node (MR-STOR) | 147 | 28 | 36 | 49 | 16 | 17 | 1 |
| Storage §14 lines added after the pin (STOR-014) | 11 | 9 | 1 | 1 | 0 | 0 | 0 |
| **All** | **894** | **319** | **230** | **97** | **31** | **63** | **154** |

## 8 Per-requirement results

### 8.1 DSM high-level explainer

| MR-ID | Status | Code (crate · file · function) | Test | Gap / note |
|---|---|---|---|---|
| MR-DSM-0001 | Partial | dsm · types/device_state.rs · `advance` (balance subtraction only); economic/register.rs · `economic_root_register_key` (SoFi economic position only) | economic_lineage_register::each_position_of_each_identity_is_its_own_cell | Registration of every value-moving advance is in place (G6 withdrawn); the general κres/Σ consumption model the theorem is stated over is absent (G3). |
| MR-DSM-0002 | Partial | dsm · types/device_state.rs · `advance`; dsm_sdk · sdk/receipts.rs · `verify_receipt_bytes` | `receipts::tests::first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` | Relationship-chain continuation is decidable (parent and child inclusion). The candidate and guard structure the continuation predicate needs (P, Γ) does not exist (MR-DSM-0120–0131). |
| MR-DSM-0003 | Met | dsm · types/device_state.rs · `advance` (pure over `&self`; the SDK commit is CAS, first commit wins) | `device_state::tests::concurrent_advances_from_same_root_produce_different_children` | — |
| MR-DSM-0004 | Partial | dsm_sdk · sdk/receipts.rs · `verify_receipt_bytes`; dsm · types/device_state.rs · `advance` | no test found | The recipient checks its own relationship tip. There is no committed policy component Π (MR-DSM-0126). |
| MR-DSM-0005 | Partial | dsm_sdk · sdk/receipts.rs · `verify_receipt_bytes` | `receipts::tests::first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` | Successor check tested for relationship heads. The realization predicate lacks CandidateOK and GuardOK (MR-DSM-0014). |
| MR-DSM-0006 | Not code | — | — | Part IV offline, out of scope. |
| MR-DSM-0007 | Partial | dsm · vault/limbo_vault.rs::claim (2026); vault/dlv_manager.rs::claim_vault_content (236) | no test found | Nothing in `dsm` or `dsm_sdk` calls `.claim(`, `claim_vault_content`, or exercises `Operation::DlvClaim`. |
| MR-DSM-0008 | Partial | dsm · types/state_types.rs::State::compute_hash (485-521) | — | Hashes `forward_commitment`; no guard-family digest concept exists anywhere in the file. |
| MR-DSM-0009 | Missing | dsm · types/state_types.rs::State (273-314); types/device_state.rs::DeviceState (39-90) | — | Neither `State` nor `DeviceState` carries a committed integer position. |
| MR-DSM-0010 | Missing | same as 0009 | — | No position exists to present with the root (MR-DSM-0009). |
| MR-DSM-0011 | Partial | dsm · economic/register.rs::economic_root_register_key (58-68) | economic_lineage_register::each_position_of_each_identity_is_its_own_cell | K derived from (G, DevID, position) only for this one cell type. |
| MR-DSM-0012 | Partial | dsm · economic/register.rs (write-once cell) | economic_lineage_register::registering_an_arbitrary_root_yields_nothing_validated | Stands in for Σ only for SoFi economic-position. |
| MR-DSM-0013 | Partial | dsm · economic/peer_acceptance.rs::verify_peer_transfer_acceptance (214-221); core/bilateral_transaction_manager.rs::compute_smt_key | economic_peer_evidence::a_valid_acceptance_bundle_verifies_and_every_binding_is_load_bearing; smt_tripwire_theorem::theorem1_relationship_scoped_keys | Covers SoFi peer-debit + SMT-key uniqueness; general cross-chain sharing not traced elsewhere. |
| MR-DSM-0014 | Partial | dsm · types/device_state.rs · `advance`; dsm_sdk · sdk/receipts.rs · `verify_receipt_bytes` | no test found | Structural, linearity (heads only) and policy checks exist as separate steps. CandidateOK and GuardOK have nothing to check: there is no P or Γ. |
| MR-DSM-0015 | Partial | dsm · types/device_state.rs · `advance` (returns `Result`) | no test found | No Accept predicate of named conjuncts exists (MR-DSM-0014). |
| MR-DSM-0016 | Met | dsm · types/device_state.rs · `advance` (takes `&self`; an `Err` produces no state) | `device_state::tests::advance_rejects_balance_underflow`, `advance_rejects_balance_overflow` | — |
| MR-DSM-0017 | Partial | dsm · sofi/arith.rs::CellResolution (43-51) | sofi::arith::tests::leader_held_settles_the_race_before_finality | SoFi-cell only; general Pending/Unavailable not traced. ChatGPT CG-02: the undecided status lives in Core's predicate type (see MR-SOFI-0030). |
| MR-DSM-0018 | Violated | dsm_sdk · storage/client_db/recipient_staging.rs · `mark_rejected`; handlers/recipient_accept.rs · `reject` | `recipient_staging` tests assert that a rejected pair "must stay rejected" and cannot be re-staged (they assert the forbidden behaviour) | A failed acceptance is persisted as a sticky `TerminalReject` with a reason, and re-staging the pair is refused. The spec says nothing negative is recorded. Core `advance` itself records nothing. |
| MR-DSM-0019 | Partial | dsm · sofi/arith.rs::resolve | sofi::arith::tests (multiple) | Admission wiring to a waiting caller not traced. |
| MR-DSM-0020 | Partial | dsm · types/device_state.rs · `DeviceState`, `RelationshipChainState` (no counter field) | no test found | True by field absence: no counter in `State` or `DeviceState`. No test fails if one is added. |
| MR-DSM-0021 | Partial | dsm · economic/lineage.rs (per-identity `economic_position`, no external service) | no test found | True by construction: per-identity `economic_position`, no external service. No test. |
| MR-DSM-0022 | Met | dsm · economic/lineage.rs::advance_validated (582-740) | economic_admission_lifecycle::a_faucet_claim_transition_advances_the_validated_lineage | Root + funded-credit set returned/adopted together or the call errors. |
| MR-DSM-0023 | Not code | — | — | Theorem statement. |
| MR-DSM-0024 | Partial | dsm · core/token/token_state_manager.rs::derive_canonical_balance_key (119-130) | — | Holder+policy_commit+token_id scoped, not the exact (cpta-balance,GT,PT,holder) 4-tuple. |
| MR-DSM-0025 | Missing | same as 0009 | — | No progression object u exists (MR-DSM-0009). |
| MR-DSM-0026 | Partial | dsm · economic/lineage.rs::ValidatedEconomicRoot{economic_position, economic_root} (86-89) | — | Bound together only for the SoFi economic coordinate, not the device root generally. |
| MR-DSM-0027 | Partial | dsm · economic/peer_acceptance.rs (87-147, EK-ancestry walk) | — | A generic "relationship created only after mirror-verify" gate not located outside this SoFi path. |
| MR-DSM-0028 | Met | dsm · economic/peer_acceptance.rs::resolve_expected_prev_pk (94-147) | economic_peer_evidence::ek_ancestry_walks_one_step_and_refuses_unhashed_substitution | — |
| MR-DSM-0029 | Partial | ordering not located on the production path | no test found | The earlier locus (transition.rs) has no production caller. |
| MR-DSM-0030 | Partial | dsm_sdk · handlers/app_router_impl.rs · `process_online_transfer_logic` → sdk/economic_admission_flow.rs · `finish_admission` → `register_economic_root`; handlers/token_routes.rs · `handle_token_mint`, `handle_token_burn` → `admitted_self_loop_operation` | none | Reconciled Violated → Partial (G6 withdrawn): every value-moving advance registers its root at the next economic position, in the SDK rather than in Core. No test fails if the send path stops registering. |
| MR-DSM-0031 | Met | dsm · economic/register.rs::economic_root_register_key (58-68) | economic_lineage_register::each_position_of_each_identity_is_its_own_cell | — |
| MR-DSM-0032 | Met | dsm · economic/register.rs::position_leader (91-101) | sofi::fisher_yates::tests::different_seeds_can_choose_different_first_members | — |
| MR-DSM-0033 | Met | dsm · economic/register.rs::RegisteredEconomicRoot::from_verified_single_root (422-434) | economic::register::registered_root_construction_tests::{a_registered_root_is_a_projection_of_a_verified_claim, a_conditional_claim_has_nothing_to_construct_from} | — |
| MR-DSM-0034 | Partial | dsm_sdk · sdk/storage_node_sdk.rs::put_cell_leader_first (1475-1506) | — | Leader-first order confirmed; no accumulated chain object threaded between writes (A6 not implemented). |
| MR-DSM-0035 | Met | dsm · sofi/arith.rs::resolve (60-82) | sofi::arith::tests::a_later_value_at_the_leader_never_becomes_final | — |
| MR-DSM-0036 | Violated | dsm · sofi/arith.rs::resolve | sofi::arith::tests::the_leaders_first_value_held_by_two_others_is_final (proves the actual count-based mechanism) | Count-based (2-of-4 copies), not the A6 three-link route chain; storage_cell.rs's new ArrivalRecord/ByteCommit primitives are unconsumed by `resolve`. |
| MR-DSM-0037 | Met | dsm · sofi/arith.rs::resolve (64-70) | sofi::arith::tests::an_unreachable_leader_resolves_nothing_and_no_member_stands_in | — |
| MR-DSM-0038 | Met | dsm · economic/lineage.rs::advance_validated (599-616) | economic_admission_lifecycle::a_registered_root_disagreeing_with_the_witness_is_refused | `advance_validated` refuses a registered root that disagrees with the witness. |
| MR-DSM-0039 | Partial | dsm · economic/lineage.rs::advance_validated (605-610) | — | Registration-then-accept order enforced; finality half of the conjunction depends on arith.rs's pre-A6 mechanism (0036). |
| MR-DSM-0040 | Met | dsm · economic/lineage.rs::advance_validated (611-616) | economic_admission_lifecycle::a_faucet_claim_transition_advances_the_validated_lineage | — |
| MR-DSM-0041 | Partial | ordering not located on the production path | no test found | The earlier locus (transition.rs) has no production caller. ChatGPT CG-03: SoFi resolution reads registration before evaluating conformance evidence already in hand. |
| MR-DSM-0042 | Partial | ordering not located on the production path | no test found | The earlier locus (transition.rs) has no production caller. ChatGPT CG-03 (see MR-DSM-0041). |
| MR-DSM-0043 | Met | dsm · economic/register.rs (58-68, 405-467) | economic_lineage_register::each_position_of_each_identity_is_its_own_cell | — |
| MR-DSM-0044 | Not code | — | — | Operator durability property. |
| MR-DSM-0045 | Not code | — | — | Offline/recovery, out of scope. |
| MR-DSM-0046 | Partial | dsm · sofi/arith.rs | — | SoFi-only; general framing not traced. |
| MR-DSM-0047 | Met | dsm · core/bilateral_transaction_manager.rs::compute_smt_key (146-156); types/device_state.rs::RelationshipChainState.rel_key (262) | smt_tripwire_theorem::theorem1_relationship_scoped_keys | `compute_smt_key` = BLAKE3(min(id)‖max(id)) IS the per-device SMT leaf key and is directly tested for distinctness/order-invariance across device pairs. |
| MR-DSM-0048 | Met | dsm · economic/peer_acceptance.rs (214-221, 300-306) | economic_peer_evidence::a_valid_acceptance_bundle_verifies_and_every_binding_is_load_bearing | — |
| MR-DSM-0049 | Met | dsm · economic/peer_acceptance.rs (same) | same test (different recipient devid / different child tip both rejected) | — |
| MR-DSM-0050 | Partial | dsm · economic/peer_acceptance.rs + economic/provenance.rs (FundedCredit) | no test found | Structurally consistent (receipt funds a credit without advancing sender's chain) but no dedicated test for the specific cross-relationship-evidence scenario. |
| MR-DSM-0051 | Partial | dsm_storage_node · api/cells.rs, api/objects/immutable.rs (no key material referenced) | no test found | No dedicated test; only checked these two handler modules, not exhaustive. |
| MR-DSM-0052 | Met | dsm_storage_node · api/cells.rs::put_cell/put_cells | cells_keep_everything::only_malformed_requests_are_refused | — |
| MR-DSM-0053 | Met | dsm_storage_node · api/objects/immutable.rs::put_immutable/get_immutable | immutable_store_round_trip (+ inline `proto_decodable_bytes_are_just_bytes`) | — |
| MR-DSM-0054 | Met | dsm_storage_node · api/objects/immutable.rs (no decode path) | immutable.rs::tests::proto_decodable_bytes_are_just_bytes | — |
| MR-DSM-0055 | Partial | dsm_storage_node · api/objects/immutable.rs (uses `state.current_tick`, 123) | — | Not exhaustively checked across every module. |
| MR-DSM-0056 | Partial | dsm_storage_node · replication.rs; api/transport/gossip.rs | — | No Raft/Paxos/vote code found; inherently a negative claim, no test asserts it. |
| MR-DSM-0057 | Partial | dsm_storage_node · api/vault/paidk.rs::require_paidk (44); wired in objects/store.rs (230,319), transport/b0x.rs (285) | paidk_gating::t_e_cross_endpoint_sweep_unpaid_rejects | That test calls the helper directly, not the routes; api/cells.rs and api/identity/tips.rs have **no** gate of any kind — confirmed by direct grep (no "paidk" hits). |
| MR-DSM-0058 | Missing | dsm_storage_node · api/vault/paidk.rs | — | The testable clause (route chain needs 3 links before a write "goes through") is the same absent A6 mechanism as 0036/0034/0083 — a real gap, not a non-requirement. (Payment-split policy itself is genuinely spec-Open.) |
| MR-DSM-0059 | Missing | — | — | No opt-out/network-cut code found anywhere in `dsm_storage_node` or `dsm`. |
| MR-DSM-0060 | Violated | dsm_storage_node · api/objects/store.rs::put_object (229-231) | — | Gates on `device_ctx.device_id` (writer), not `dlv_id_b` (account written to). |
| MR-DSM-0061 | Partial | dsm_storage_node · api/objects/store.rs::put_object | — | PaidK applies uniformly to every write; no exemption for post-creation DLV writes. |
| MR-DSM-0062 | Partial | dsm_storage_node · api/vault/paidk.rs; db::upsert_object_with_capacity_check (pg.rs) | paidk_gating tests | No client-side "check own balance before acting" found; FLAT_RATE is a hardcoded constant. |
| MR-DSM-0063 | Partial | dsm · storage_object.rs::immutable_addr; dsm_storage_node · api/objects/immutable.rs::put_immutable (106) | no test found | Code is solid but no test asserts the address-derivation formula specifically. |
| MR-DSM-0064 | Partial | dsm_storage_node · api/objects/immutable.rs::put_immutable (109-121, x-expected-addr compare) | no test found | Mismatch path (UNPROCESSABLE_ENTITY) is untested. |
| MR-DSM-0065 | Violated | dsm_storage_node · db/pg.rs::upsert_object (1316-1333, `ON CONFLICT DO UPDATE`), reachable via api/objects/store.rs::put_object (117, `/api/v2/object/put`) | — | Confirmed live overwrite path. |
| MR-DSM-0066 | Partial | dsm_storage_node · api/objects/immutable.rs::put_immutable (137-149) | immutable_store_round_trip::re_putting_identical_bytes_acks_and_the_read_is_unchanged | The suite runs on Postgres since the SQLite backend was deleted (2026-09-24). |
| MR-DSM-0067 | Partial | dsm_storage_node · api/objects/immutable.rs::get_immutable (177-187) | no test found | Code recomputes on read, but no test stores a corrupted tuple to prove refusal. |
| MR-DSM-0068 | Partial | dsm_sdk · sdk/storage_node_sdk.rs::StorageNodeSDK::fetch_immutable_verified (1715-1755); sdk/storage_io.rs::fetch_immutable_payload (205-256) | no test found | Production-path client re-hash code located precisely; no test exercises a hostile/mismatched node response. |
| MR-DSM-0069 | Met | dsm_storage_node · api/identity/tips.rs (33-41, 21-31) | identity::tips::tests (inline, ~137-197) | — |
| MR-DSM-0070 | Partial | dsm_storage_node · api/transport/b0x.rs (spool insert/retrieve/ack, 190-212+) | `b0x.rs::a_submitted_envelope_is_read_back_from_its_spool` (Postgres) | The spool round-trips a sealed envelope byte for byte; the node still decodes what it is given (storage §1 rule 2 finding stands). |
| MR-DSM-0071 | Partial | dsm_storage_node · api/transport/b0x.rs::submit_b0x_envelope (238+, only decodes outer Envelope) | no test found | Code never inspects inner payload, but no dedicated negative test. |
| MR-DSM-0072 | Violated | dsm_storage_node · api/transport/b0x.rs::router (190-212, wraps `/api/v2/b0x/submit` in `device_auth`) | — | — |
| MR-DSM-0073 | Partial | dsm_storage_node · api/transport/b0x.rs::valid_spool_key (59-64) | no test found | 32-byte check confirmed, no dedicated test located. |
| MR-DSM-0074 | Partial | dsm_sdk · types/device_state.rs (tips map implicitly scopes known relationships) | no test found | No explicit pre-add allowlist/gate for b0x send/receive found. |
| MR-DSM-0075 | Violated | dsm_storage_node · auth/mod.rs::device_auth (126-235) | — | Same evidence as 0072. |
| MR-DSM-0076 | Not code | — | — | Recovery, out of scope. |
| MR-DSM-0077 | Met | dsm · storage_cell.rs::ByteCommit (156-229); dsm_storage_node · api/objects/bytecommit.rs | storage_cell::tests::{the_bytecommit_digest_matches_the_spec_construction, a_chain_link_needs_same_member_next_cycle_and_the_parent_digest}; bytecommit_chain::cycles_close_over_new_entries_and_commit_their_records | — |
| MR-DSM-0078 | Partial | dsm · storage_cell.rs::ByteCommit::is_drain_proof (192-198); dsm_storage_node · db/pg.rs (dlv_slots table, 802-1436) | storage_cell::tests::a_drain_proof_is_two_linked_empty_bytecommits | Drain-proof half is Met; capacity is regulated against a separate `dlv_slots` table, not against ByteCommit `bytes_used`. |
| MR-DSM-0079 | Partial | dsm · storage_cell.rs::CellCommitProof::verifies (291-297) | storage_cell::tests | Verifier primitive exists/tested; no SDK/Core consumer wiring located. |
| MR-DSM-0080 | Partial | dsm_storage_node · api/vault/paidk.rs (DEFAULT_K=3); db/pg.rs::store_payment_receipt (1978, `COUNT(DISTINCT operator_node_id)`) | paidk_gating::t_b_paid_device_accepted | That test bypasses the counting logic via `mark_paidk_satisfied` directly rather than submitting 3 distinct-operator receipts; plus 0057's gap (cells/tips ungated). |
| MR-DSM-0081 | Met | dsm · economic/register.rs::position_leader/position_seed (74-101) | sofi::fisher_yates::tests::different_seeds_can_choose_different_first_members | — |
| MR-DSM-0082 | Partial | dsm · economic/register.rs::position_seed (74-86, signature has no node-id/availability parameter) | no test found | `position_seed` takes no node id or availability input. No test fails if one is added. |
| MR-DSM-0083 | Partial | dsm_sdk · sdk/storage_node_sdk.rs::put_cell_leader_first | — | Same gap as 0034. |
| MR-DSM-0084 | Met | dsm_storage_node · api/cells.rs::put_cell/put_cells (116-180) | cells_keep_everything::{a_second_value_at_a_key_is_kept_after_the_first_never_refused, an_identical_value_put_twice_is_held_twice} | — |
| MR-DSM-0085 | Violated | dsm · sofi/arith.rs::resolve | sofi::arith::tests::the_leaders_first_value_held_by_two_others_is_final | Same evidence as 0036. |
| MR-DSM-0086 | Met | dsm · sofi/arith.rs::resolve/resolve_objects | sofi::arith::tests::the_adapter_derives_final_from_the_recognized_view | — |
| MR-DSM-0087 | Met | dsm · economic/register.rs::RegisteredEconomicRoot vs economic/lineage.rs::ValidatedEconomicRoot | economic_lineage_register::registering_an_arbitrary_root_yields_nothing_validated | — |
| MR-DSM-0088 | Not code | — | — | Operator restore-discipline assumption. |
| MR-DSM-0089 | Partial | dsm_storage_node · api/objects/immutable.rs::get_immutable (177-187) | no test found | Same gap as 0067 (same mechanism). |
| MR-DSM-0090 | Not code | — | — | Fault-model assumption. |
| MR-DSM-0091 | Not code | — | — | Dependency boundary; nothing to implement here. |
| MR-DSM-0092 | Partial | `dsm/src/types/device_state.rs::advance` (1134); `dsm_sdk/src/sdk/receipts.rs::verify_receipt_bytes` (844) | `receipts.rs::tests::first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` (3251) | New finding: the only candidate/guard mechanism in the tree (`verification::receipt_verification::verify_stitched_receipt`, using `ForkCandidate`) is wrapped by `dsm_sdk::sdk::receipts::verify_stitched_receipt` (602), which has **zero handler callers** — production acceptance (`verify_receipt_bytes`) has no candidate/guard/linearity stage at all. |
| MR-DSM-0093 | Partial | `dsm/src/types/device_state.rs::advance` (pure, operates only on `self`); `core/state_machine/mod.rs::prepare_advance_relationship/commit_advance` | no test found | Enforced structurally (no API accepts on another device's behalf) but no named test isolates this property. |
| MR-DSM-0094 | Not code | — | — | Liveness boundary; nothing to build. |
| MR-DSM-0095 | Partial | `dsm/src/types/device_state.rs` (`RelationshipChainState`/`DeviceState` fields, no counter/timestamp, confirmed by reading the struct) | no test found | True by field-absence; no negative test exercises it (transition.rs's tests are off the production path). |
| MR-DSM-0096 | Met | `dsm/src/common/canonical_encoding.rs::CanonicalEncode` (16); `dsm/src/crypto/blake3.rs::dsm_domain_hasher` | `merkle::sparse_merkle_tree::tests::default_node_chain_consistency`, `verify_proof_against_root_static` | Pure/deterministic functions, exercised widely. |
| MR-DSM-0097 | Partial | `dsm_storage_node/src/api/objects/store.rs::put_object` (130) calling `dsm_storage_node/src/api/identity/authenticate.rs::authenticate_vaultpost_smart_policy_if_present` (86) | `authenticate.rs::tests::authenticate_vaultpost_crypto_condition_empty_public_params_rejected` (204) | `put_object` does call a validator. But the check is narrow (structural decode of an *embedded* SmartPolicy only, when present); most bytes get zero validation. The requirement itself ("no storage node can make an invalid object valid") holds architecturally because validity is established independently downstream (`verify_receipt_bytes`), not because storage validates content — no test asserts that boundary directly. |
| MR-DSM-0098 | Partial | same as 0092 | `first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` | Reproducibility holds for the checks `verify_receipt_bytes` actually performs; no single "every validity decision" test since candidate/guard stage is unreachable (see 0092). |
| MR-DSM-0099 | Partial | `dsm/src/merkle/sparse_merkle_tree.rs`; `dsm/src/core/bilateral_transaction_manager.rs:146` (`compute_smt_key`) | `smt_replace_witness::tests::smt_key_is_order_invariant` (197) | Hashing/SMT/key derivation deterministic and tested; guard/policy evaluation not a unified deterministic mechanism (doesn't exist — see 0148/0149). |
| MR-DSM-0100 | Met | `dsm/src/common/canonical_encoding.rs::CanonicalEncode` | `domain_tags::mod::tests::all_tags_are_unique`, `every_declared_domain_tag_reaches_the_registry` | Digests taken over canonical bytes throughout. |
| MR-DSM-0101 | Partial | `dsm/src/types/proto.rs` (prost-generated); `dsm/src/common/canonical_encoding.rs` (CBOR module explicitly removed) | no test found | Proto.rs has no hand-written tests (generated code); "protobuf-only" is enforced by removal of alternatives, not asserted by a positive test. |
| MR-DSM-0102 | Partial | `dsm/src/types/device_state.rs` field `balances: BTreeMap<[u8;32],u64>` (61) | no test found | Production sorting is implicit via `BTreeMap` iteration order; no test asserts two equal `DeviceState`s encode identically. |
| MR-DSM-0103 | Partial | `dsm/src/common/canonical_encoding.rs:25-37` (comment + removed `cbor` module); confirmed no hex/base64/json/cbor imports in `device_state.rs` | no test found. `ci/production_safety_checks.sh` has no hex, JSON or CBOR check (verified by reading it). | Banned by removal only; nothing fails if hex, JSON or CBOR returns to a canonical encoding. |
| MR-DSM-0104 | Partial | `dsm/src/types/device_state.rs::relationship_chain_tip_v2` (300) | `device_state.rs::tests::the_chain_tip_commits_succession_facts_and_no_balances` (3205) | Canonical encoding governs the chain tip; broad claim (governs "guards, SMT leaves, resource keys, policy, proofs") not testable as one unit since several of those don't exist yet. |
| MR-DSM-0105 | Met | `dsm/src/common/domain_tags/**`; `dsm/src/merkle/sparse_merkle_tree.rs:45-62` | `domain_tags::mod::tests::all_tags_are_unique` (31), `no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it` (63), `no_registered_tag_can_carry_a_nul_by_construction` (103) | Strong test coverage of domain separation. |
| MR-DSM-0106 | Not code | — | — | Cryptographic assumption (BLAKE3 collision resistance), not implementable/testable in-repo. |
| MR-DSM-0107 | Met | `dsm/src/types/device_state.rs::relationship_chain_tip_v2` (embeds `embedded_parent`) | `device_state.rs::tests::tripwire_same_relationship_same_parent_different_children` (3399) | — |
| MR-DSM-0108 | Met | `dsm_sdk/src/sdk/receipts.rs::verify_receipt_bytes` (parent/child inclusion + replace-recompute, 896-925) | `receipts.rs::tests::first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` (3251) | Test asserts a receipt built against the wrong root fails verification. |
| MR-DSM-0109 | Met | `dsm/src/core/bilateral_transaction_manager.rs::compute_smt_key` (146) | `merkle::sparse_merkle_tree::tests::multi_leaf_proofs` (639) | Distinct keys, independent leaves. |
| MR-DSM-0110 | Met | `dsm/src/types/device_state.rs::advance` (single leaf replace, 1134) | `sparse_merkle_tree::tests::multi_leaf_proofs`, `leaf_update_changes_root` | — |
| MR-DSM-0111 | Partial | `dsm/src/merkle/sparse_merkle_tree.rs::update_leaf` (176-198) | `leaf_update_changes_root` | No named per-relationship transition function `f_r`; leaf-replace is generic, not a relationship-specific deterministic rule object. |
| MR-DSM-0112 | Met | `dsm/src/types/device_state.rs::advance` (conservation/admission gates read only `self` + named relationship) | `device_state.rs::tests::conservation_guard_rules` (2251) | — |
| MR-DSM-0113 | Met | `dsm/src/merkle/sparse_merkle_tree.rs::get_inclusion_proof/verify_inclusion_proof` | `update_and_prove` (602), `multi_leaf_proofs` (639) | — |
| MR-DSM-0114 | Met | `sparse_merkle_tree.rs::default_node`/`DEFAULT_SMT_HEIGHT=256` (37) | `default_node_chain_consistency` (589), `empty_tree_root_matches_default_chain` (583) | — |
| MR-DSM-0115 | Met | `bilateral_transaction_manager.rs::compute_smt_key` (146) | `verification::smt_replace_witness::tests::smt_key_is_order_invariant` (197); also `verification::receipt_verification::tests::test_smt_key_ordering` (327) | — |
| MR-DSM-0116 | Violated | dsm · merkle/sparse_merkle_tree.rs · `update_leaf` (FIFO eviction past `max_leaves`); dsm_sdk · sdk/core_sdk.rs genesis (`max_relationships = 1024`) | `sparse_merkle_tree::tests::cache_eviction_fifo` (asserts the eviction) | Past 1024 relationships the oldest head is silently evicted and then reads as absent. |
| MR-DSM-0117 | Met | `sparse_merkle_tree.rs::update_leaf` | `leaf_update_changes_root`, `multi_leaf_proofs` | — |
| MR-DSM-0118 | Met | `sparse_merkle_tree.rs::verify_proof_against_root` (path recompute) | `verify_proof_against_root_static` (618), `update_and_prove` | — |
| MR-DSM-0119 | Met | `sparse_merkle_tree.rs::DEFAULT_SMT_HEIGHT=256`, `get_inclusion_proof` | `proof_size_bounding` (740) | — |
| MR-DSM-0120 | Missing | — | — | Confirmed by direct grep for `rho_core`/`core_root`/`struct Candidate`/`GuardFamily`/`κres`: zero hits in `dsm/src`. `DeviceState` has a single flat root, no P/Γ/Ω. |
| MR-DSM-0121 | Violated | same as MR-DSM-0116 | `sparse_merkle_tree::tests::cache_eviction_fifo` | Same FIFO eviction: R stops mapping evicted relationships to their heads. |
| MR-DSM-0122 | Partial | `dsm/src/types/device_state.rs::RelationshipChainState::embedded_parent` (per-relationship ordering only) | no test found | No state-level `u` (sequence digest/progression coordinate) exists. |
| MR-DSM-0123 | Missing | — | — | No committed candidate structure `P`. |
| MR-DSM-0124 | Missing | — | — | No `Γ` structure. |
| MR-DSM-0125 | Partial | `dsm/src/economic/state.rs::EconomicConsumedSourceState` (84) | no test found in `economic/state.rs` (zero `#[test]` in file) | Write-once leaf exists only for economic sources, not a general `Σ`. |
| MR-DSM-0126 | Partial | `dsm/src/cpta/mod.rs` | not checked in depth | Policy data exists but is not committed into the state root as `Π`. |
| MR-DSM-0127 | Missing | — | — | No `Ω` component in `DeviceState`. |
| MR-DSM-0128 | Met | `dsm/src/types/device_state.rs::root()` (818) | exercised throughout `device_state.rs` tests (e.g. `current_state_always_reflects_the_canonical_head_never_an_override` in `mod.rs:341`) | — |
| MR-DSM-0129 | Missing | `dsm/src/types/device_state.rs::root()` | — | Single flat root; no separate `ρcore` excluding candidate/guard space (because no such space exists). |
| MR-DSM-0130 | Missing | — | — | No candidates/guards to bind. |
| MR-DSM-0131 | Missing | — | — | No `H(ρcore‖digest(P)‖digest(Γ))` construction. |
| MR-DSM-0132 | Missing | — | — | No such dependency graph exists. |
| MR-DSM-0133 | Met | `dsm/src/types/device_state.rs::advance` (embedded_parent must equal current committed tip) | `tripwire_same_relationship_same_parent_different_children` (3399) | Enforced by the `embedded_parent` binding and the receiver's inclusion-proof check. |
| MR-DSM-0134 | Partial | `dsm/src/types/device_state.rs::root()` | — | Current facts committed; permitted-transition structure (P, Γ) is not, because it doesn't exist. |
| MR-DSM-0135 | Met | `dsm/src/types/device_state.rs::advance` (pure fn of `&self` + args, no external history param) | `tripwire_same_relationship_same_parent_different_children` | — |
| MR-DSM-0136 | Met | `dsm/src/types/device_state.rs::RelationshipChainState` fields (no counter/height/timestamp) | `the_chain_tip_commits_succession_facts_and_no_balances` (3205, corroborating) | — |
| MR-DSM-0137 | Missing | — | — | No parent-committed candidate space. |
| MR-DSM-0138 | Missing | `dsm/src/commitments/precommit.rs::ForkCandidate` (121) | — | `ForkCandidate { fork_id: String, payload: Vec<u8>, entropy: Vec<u8> }` lacks a guard descriptor and a resource-key set — does not match `(s_i,b_i,g_i,K_i,d_i)` even structurally. |
| MR-DSM-0139 | Missing | — | — | No candidate-to-parent binding exists (no candidate exists). |
| MR-DSM-0140 | Partial | `dsm/src/types/device_state.rs::advance` (embedded_parent binding) | `tripwire_same_relationship_same_parent_different_children` | Effect achieved via hash-adjacency, not a committed candidate list. |
| MR-DSM-0141 | Partial | `dsm/src/commitments/precommit.rs`; `dsm_sdk/src/sdk/dlv_pre_commitment_sdk.rs` (34 tests, 520-1073) | tests exist in-file but not production-reachable | No handler calls `DlvPreCommitmentSdk`. |
| MR-DSM-0142 | Partial | `dsm/src/merkle/sparse_merkle_tree.rs` (relationship heads); `dsm/src/economic/state.rs` (economic sources); NOT `dsm/src/vault/dlv_manager.rs` (33-47) | dlv_manager.rs has exactly one `#[test]` in file (`dlv_manager_default`, line 404 — a trivial constructor check) | Re-read the doc comment at dlv_manager.rs:33-47 directly: confirms "double-claim across stitched receipts" is explicitly documented as NOT enforced. |
| MR-DSM-0143 | Missing | — | — | Precommitment is not part of canonical state evolution anywhere in `DeviceState`. |
| MR-DSM-0144 | Missing | — | — | No P/Γ chaining across generations (P/Γ don't exist). |
| MR-DSM-0145 | Partial | `dsm/src/types/device_state.rs::advance` (embedded_parent equality is the closest analog) | `tripwire_same_relationship_same_parent_different_children` | Not a committed-candidate check; hash-adjacency substitute. |
| MR-DSM-0146 | Missing | `dsm/src/vault/limbo_vault.rs` (`claim`, `invalidate`) | — | No general deterministic guard `g_i(s,w)` abstraction; each vault op has its own bespoke check. |
| MR-DSM-0147 | Partial | SPHINCS+ sigs (`crypto/sphincs.rs`); `vault/limbo_vault.rs`; `dsm_sdk/src/sdk/receipts.rs`; `dsm/src/recovery/succession_proof.rs` | tests exist per-type (e.g. `limbo_vault.rs::tests::a_policy_digest_altered_after_signing_fails_verify`, 2899) | Witness types exist individually, each independently tested, but not unified under one guard-family interface. |
| MR-DSM-0148 | Missing | — | — | Confirmed: no type binds parent + branch id + resource keys + witness type + predicate + conflict class together. |
| MR-DSM-0149 | Missing | — | — | No guard family exists. |
| MR-DSM-0150 | Not code | — | — | Proof-methodology statement about a mechanism (guard families) that doesn't exist. |
| MR-DSM-0151 | Missing | — | — | No conflict-class key derivation abstraction. |
| MR-DSM-0152 | Partial | `dsm/src/types/device_state.rs::advance` (SMT-leaf CAS for heads); `dsm/src/economic/state.rs::EconomicConsumedSourceState` (write-once) | `tripwire_same_relationship_same_parent_different_children`; no test found for economic write-once | Holds for relationship heads and economic sources; not for DLV vault generations (dlv_manager.rs gap, see 0142). |
| MR-DSM-0153 | Partial | SMT leaf = `(rel_key, embedded_parent)` per `RelationshipChainState` | `multi_leaf_proofs` | No general resource-descriptor abstraction beyond relationships. |
| MR-DSM-0154 | Partial | `bilateral_transaction_manager.rs::compute_smt_key` (keys derived from committed devids, not caller-chosen) | `smt_key_is_order_invariant` | No general anti-evasion abstraction across resource types. |
| MR-DSM-0155 | Missing | `dsm/src/common/domain_tags/dsm/misc/economic.rs:40-46` (`consumed_source` key = `H(tag‖0x00‖G‖DevID‖source_id)`) | no test found | Consumed-source key is bound to `(G, DevID, source_id)`, **not** to `ρcore` as the spec's `κres(s,x)` formula requires — confirmed by reading the file's own doc comment ("key is derived from the state… (G, DevID)"), which is a different binding than the normative formula. |
| MR-DSM-0156 | Partial | as 0155 | no test found | Same resource → same key holds for the mechanism that exists, but that mechanism isn't `κres(s,x)`. |
| MR-DSM-0157 | Partial | as 0154/0155 | `smt_key_is_order_invariant` | Exclusion key derived from resource identity, not from the branch — holds for the two existing mechanisms only. |
| MR-DSM-0158 | Not code | — | — | Negative claim about branch-local identifiers never being authoritative; nothing to implement, nothing found that violates it either. |
| MR-DSM-0159 | Missing | — | — | No `CK(s)` conflict-class-membership abstraction. |
| MR-DSM-0160 | Partial | `dsm/src/economic/state.rs::EconomicConsumedSourceState` (write-once); `dsm/src/merkle/sparse_merkle_tree.rs::update_leaf` (CAS) | no test found for the economic non-inclusion-before-write path specifically | Mechanism exists piecewise, no unified `Σ`. |
| MR-DSM-0161 | Partial | same as 0160 | no test found | Monotonicity is structural (no leaf-delete path exists) but untested directly. |
| MR-DSM-0162 | Partial | `dsm/src/economic/state.rs`; `sparse_merkle_tree.rs::get_inclusion_proof` (non-inclusion vs inclusion) | `update_and_prove` (SMT mechanics only, not economic-specific) | — |
| MR-DSM-0163 | Partial | `dsm/src/types/device_state.rs::advance` (structural + conservation + admission-fence checks composed) | `conservation_guard_rules` (2251), `a_builtin_token_cannot_be_minted_from_air_at_the_accepting_transition` (1960) | No CandidateOK/GuardOK stage (doesn't exist); the other four conjuncts are approximated by different, narrower checks. |
| MR-DSM-0164 | Partial | `dsm/src/types/device_state.rs::advance`; `dsm/src/economic/state.rs` | `balance_conservation_across_sequence` (3544) | Holds for heads/economic sources; not for DLV generations (0142 gap). |
| MR-DSM-0165 | Met | `dsm/src/types/device_state.rs::advance` (reads `self.chain_tip` fresh each call) | `tripwire_same_relationship_same_parent_different_children` | — |
| MR-DSM-0166 | Partial | as 0165 for heads; `dsm/src/economic/state.rs` for sources; **not** `dsm/src/vault/dlv_manager.rs` | `tripwire_same_relationship_same_parent_different_children` demonstrates the two branches are distinguishable but does **not** assert a verifier actually rejects the second one (no CAS-rejection assertion in-file) | Theorem holds for relationship heads via CAS at the persistence layer (not exercised by a unit test here — CAS lives outside this crate, in the SDK's storage commit path) and economic sources; explicitly not enforced for DLV vault generations (dlv_manager.rs doc comment). |
| MR-DSM-0167 | Not code | — | — | Proof-technique statement about "selector families," a formal concept with no corresponding code object (no guard family exists to select over). |
| MR-DSM-0168 | Partial | as 0166 | — | Holds where the shared-key/CAS mechanism exists (heads, economic sources); not for DLV multi-branch vaults. |
| MR-DSM-0169 | Not code | — | — | Machine-checked invariant is a formal-methods obligation (TLA+/Lean), out of scope for these Rust crates per this round's authority order. |
| MR-DSM-0170 | Partial | `dsm_sdk/src/sdk/dlv_pre_commitment_sdk.rs` (constructible, unreachable in production); `dsm/src/vault/dlv_manager.rs` | — | Conflicting forks are constructible in the unreachable SDK module; for the reachable DLV path, nothing prevents constructing conflicting claims (0142/0166 gap) — the tripwire property is unenforced there. |
| MR-DSM-0171 | Not code | — | — | Liveness boundary; nothing to build. |
| MR-DSM-0172 | Met | `dsm/src/merkle/sparse_merkle_tree.rs` (independent per-leaf updates) | `multi_leaf_proofs` (639) | Disjoint relationships (distinct SMT keys) commute by construction. |
| MR-DSM-0173 | Met | `dsm/src/types/device_state.rs::advance` (balance delta application, 1428-1446) | `balance_conservation_across_sequence` (3544) | — |
| MR-DSM-0174 | Partial | `dsm/src/types/device_state.rs::advance` (conservation) + CAS/write-once (linearity) | `balance_conservation_across_sequence`; `concurrent_advances_from_same_root_produce_different_children` (3321) | Both hold for heads/economic sources; not proven end-to-end for DLV vault generations. |
| MR-DSM-0175 | Partial | `dsm/src/vault/limbo_vault.rs::invalidate` (2147, terminal-state match at 2155-2168); `claim` | `vault_state_limbo_ne_active` (2640) tests enum discriminants only — **no test exercises the actual terminal-exclusivity guard** (e.g. that a Claimed vault's `invalidate()` call is rejected) | The guard exists (`invalidate` refuses a vault already `Claimed` or `Invalidated`), but the only test compares enum discriminants; nothing exercises the refusal. |
| MR-DSM-0176 | Partial | same as 0175 | same gap | True within one `LimboVault` instance's state machine; not enforced against independently-constructed conflicting stitched receipts (0142 gap). |
| MR-DSM-0177 | Partial | `dsm/src/commitments/smart_commitment.rs::SmartCommitment::evaluate` (594-661) | `smart_commitment.rs::tests::test_smart_commitment_creation_types_compile` (1570) and others | `SmartCommitment` is tested in `dsm`; its SDK wrapper `SmartCommitmentSdk` has no callers. |
| MR-DSM-0178 | Missing | `dsm/src/commitments/smart_commitment.rs::SmartCommitment` struct (136-163) | — | Confirmed by reading the struct: fields are `id, origin_state_hash, commitment_hash, conditions, operation, verification_positions, commitment_type, recipient, amount, value, parameters, signatures, planned_step` — no invariants, external-commitment, encumbrance, intent-bound, or evaluation-budget fields. |
| MR-DSM-0179 | Partial | `smart_commitment.rs::evaluate` (594-661: finite `And`/`Or` recursion, checked-arithmetic-comparable operators, SPHINCS+ verify) | tests exist (e.g. `test_compound_commitment`, 1533) | Same as MR-DSM-0177: the SDK wrapper has no callers. |
| MR-DSM-0180 | Partial | same as 0179 (no dynamic dispatch, `eval_condition` recursion is over a fixed enum, not unbounded) | same tests | No declared static evaluation budget field exists (consistent with 0178); also unreachable in production. |
| MR-DSM-0181 | Partial | `dsm::ccb::state::VaultStateV2.iteration_budget` (state.rs:345, encode L387-394); `dsm::ccb::decode::vault_state_at` (decode.rs:370-378); `dsm::vault::fulfillment::FulfillmentMechanism::BitcoinHTLC.refund_iterations` (fulfillment.rs:74-89) | no test found | `VaultStateV2.iteration_budget` exists but is only ever `None` (`ccb/mod.rs`) and is never read or decremented. No working decrementing budget exists. |
| MR-DSM-0182 | Met | `dsm::commitments::smart_commitment::CommitmentCondition` (smart_commitment.rs:45-61); `SmartCommitment::compute_commitment_hash` (L192-215); `SmartCommitment::new` (L220-249) | `dsm::commitments::smart_commitment::tests::test_compound_commitment` | — |
| MR-DSM-0183 | Partial | same as 0182 | no test found | Closed-enum exhaustive match gives structural enumerability, but no test asserts a bounded/enumerable candidate space or static budget explicitly; overlaps 0181's missing budget. |
| MR-DSM-0184 | Met | `dsm::commitments::external_commitment::{create_external_commitment L130, verify_external_commitment L152}`; `dsm::core::bridge` `ExternalCommit` handler (bridge.rs:633-657, compares hash, never executes payload) | `dsm::commitments::external_commitment::tests::test_verify_external_commitment` | — |
| MR-DSM-0185 | Partial | `dsm::types::device_state::DeviceState` (one leaf per relationship key; a step touches only its own leaf; no cross-chain lock construct) | no test found | No test isolates the liveness-boundary claim (refusal on one chain not affecting another bound by the same external commitment). |
| MR-DSM-0186 | Partial | dsm · types/device_state.rs · `advance` (per-mechanism checks only) | no test found | K∉Σ is enforced per-mechanism (signature presence), not via a general authority-vs-consumption abstraction. |
| MR-DSM-0187 | Partial | `dsm::vault::fulfillment::FulfillmentMechanism::BitcoinHTLC` refund/abort branches; `dsm::sofi::*` + `dsm_sdk::sdk::sofi_*` (sofi_advance.rs, sofi_relay.rs, etc.) | sofi unit tests exist but only exercise the dark module | Confirmed unreachable: zero `sofi` references in `proto/dsm_app.proto` message names or `dsm_sdk/src/jni/*`; `resolve_pending_position` (sofi_advance.rs:505) is called only from its own tests (lines 1008-1462); `economic_admission_flow::resume_pending_admission` explicitly fences and refuses `SofiFulfillment` pending admissions rather than processing them. |
| MR-DSM-0188 | Partial | dsm · types/device_state.rs · `advance`; vault/dlv_manager.rs · `DLVManager` (no cross-receipt consumption key) | no test found | No cross-receipt consumption key exists in `dlv_manager.rs`. |
| MR-DSM-0189 | Met | `dsm::core::token::policy::policy_enforcement::PolicyEnforcer::enforce_policy` (L245), `check_condition` (L304) | `...policy_enforcement::tests::identity_constraint_denies` | — |
| MR-DSM-0190 | Met | `policy_enforcement::check_vault_condition` (L539); `dsm::economic::write_set::{build_write_set L623, verify_operation_write_set L918}`; `dsm::economic::admission` | `...write_set::tests::a_creation_whose_every_binding_holds_produces_the_write_set`; `...policy_enforcement::tests::vault_min_balance_needs_witness` | — |
| MR-DSM-0191 | Partial | same enforcement funnel as 0190 | no exhaustive test found | The enforcement funnel exists for the paths exercised; nothing shows that no operation (including wrap and vault placement) bypasses it. |
| MR-DSM-0192 | Met | `dsm::economic::register::{economic_root_register_key L58, RegisteredEconomicRoot L406}`; `write_set.rs`; `admission.rs` | `...register::tests::a_registered_root_is_a_projection_of_a_verified_claim` | — |
| MR-DSM-0193 | Partial | `policy_enforcement::check_vault_condition` (L539) | no test found | Tests show vault conditions enforced additively, not that a vault can only narrow and never loosen the token's own policy. |
| MR-DSM-0194 | Partial | `dsm::types::policy_types::PolicyCondition` (policy_types.rs:139-215, closed enum, no pair-enumeration variant) | no test found | Structural absence satisfies the requirement, but no test asserts it. |
| MR-DSM-0195 | Not code | — | — | Rationale/safety-assumption. |
| MR-DSM-0196 | Not code | — | — | Emissions dependency boundary (out of scope this round). |
| MR-DSM-0197 | Met | `dsm::economic::native_reserve::NativeReserveState::genesis` (L153-161, fixed `ERA_RESERVE_GENESIS_SUPPLY`); builtin-mint refusal in `dsm::types::device_state::State::advance` | `dsm::types::device_state::tests::a_builtin_token_cannot_be_minted_from_air_at_the_accepting_transition`; `dsm::economic::native_reserve::tests::no_valid_reserve_transition_can_mint_era` | — |
| MR-DSM-0198 | Deferred | — | — | DBTC, excluded this round. |
| MR-DSM-0199 | Partial | dsm · types/device_state.rs · `advance` (`embedded_parent`); dsm_sdk · sdk/receipts.rs · `verify_receipt_bytes` | `receipts::tests::first_ever_receipt_requires_merkle_pre_root_not_cas_parent_root` | Parent binding holds. There is no committed index (MR-DSM-0009). |
| MR-DSM-0200 | Met | `dsm::core::contact_manager::DsmContactManager::add_verified_contact` (contact_manager.rs:236); `bilateral_transaction_manager.rs`; `relationship.rs` | `dsm::core::contact_manager::tests::test_dsm_contact_manager_add_contact` | — |
| MR-DSM-0201 | Missing | `dsm::core::state_machine::transition` (`Operation::Noop` is a legitimate named sentinel, L541/1100 — not a general zero-effect refusal) | no test found | No code refuses an arbitrary operation whose application produces no state delta; `Noop` is a distinct, permitted variant, not a guard against zero-effect transitions in general. |
| MR-DSM-0202 | Partial | `dsm_storage_node::api::vault::paidk::{require_paidk L44, submit_receipt L66}`; the no-op rate limiter that stood here is deleted (2026-09-24) | none | Byte-metered storage-credit charging per §17 is not built. |
| MR-DSM-0203 | Partial | `dsm_sdk::sdk::dlv_sdk::DlvSdk::create_vault` (L207); `dsm_sdk::handlers::token_routes` (`dlv.create` policy resolution, referenced L638); `dsm::vault::limbo_vault` | `dsm_sdk::sdk::dlv_sdk::tests::test_sdk_vault_creation` exists but only asserts non-empty vault id / pubkey length, not that reserves and spendable balance are disjoint (no second spendable copy) | The one test (`test_sdk_vault_creation`) checks a non-empty vault id and key length, not that reserves and spendable balance are disjoint. |
| MR-DSM-0204 | Met | `proto/dsm_app.proto::DlvSpecV1` (L963-979, policy_digest committed at creation); `policy_enforcement::check_vault_condition` (L539, re-checked each transition) | `...policy_enforcement::tests::vault_min_balance_needs_witness` | — |
| MR-DSM-0205 | Partial | dsm · vault/limbo_vault.rs · `claim` (no production caller); SoFi vault path (no production entry) | no test found | SoFi market production path (funded vault as pre-committed authority moving to an absent owner's live trader) is dark, per 0187/0206 findings. |
| MR-DSM-0206 | Met | `dsm::route_chain::Route::of` / `Route::leader` over `dsm::sofi::fisher_yates` (the attempt cell's route, `sofi::exercise::AttemptCell::new`) | `sofi::exercise::tests::an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s`; `...an_attempt_cells_leader_is_bound_to_the_vault_and_the_parent_root` | Function property; reached from live `sofi_exercise` (§6.8). |
| MR-DSM-0207 | Met | `dsm::sofi::exercise::{recognize_exercise L49, attempt_resolution L129}` | `dsm::sofi::exercise::tests::an_exercise_names_exactly_the_keys_its_fulfillment_and_precommit_name` | Structural binding, tested at library level; SoFi has no production entry (§3 G1). |
| MR-DSM-0208 | Partial | `dsm::sofi::arith::resolve` (arith.rs:60-82, quorum-count of `STORAGE_FINALITY_COUNT` copies); `dsm::storage_cell` (arrival-record/ByteCommit primitives, §14/§15, no route-chain evaluator) | `dsm::sofi::arith::tests::the_leaders_first_value_held_by_two_others_is_final` | Confirmed: the *live* resolver implements the pre-Amendment-A6 majority-copy model, not A6's leader+2-further-route-chain-links model; `storage_cell.rs` has the newer arrival-record primitives (added in the immediately-preceding commit 28c19cfe) but nothing wires them into a route-chain finality evaluator. |
| MR-DSM-0209 | Partial | `dsm::sofi::resolution::walk` (L552); `Resolution`/`route_impossible` (L382-424) | `dsm::sofi::resolution::tests::the_walk_is_chunking_equivalent` | Unreachable, same as 0206. |
| MR-DSM-0210 | Met | `dsm::sofi::exercise::AttemptCell` route, seeded by `storage_seed(v, R_n)` (independent per vault) | `sofi::exercise::tests::an_attempt_cells_leader_is_bound_to_the_vault_and_the_parent_root` | Function property; tested at library level. |
| MR-DSM-0211 | Partial | `dsm::sofi::registration::{names_fulfillment_key L50, fulfillment_registered L99}` | `dsm::sofi::registration::tests::registration_needs_both_cells_final_and_the_root_on_this_claim` | Unreachable, same as 0206. |
| MR-DSM-0212 | Partial | `dsm::sofi::resolution::effect_of` (L96, `Resolution::Void ⇒ PositionEffect::InstallPreviousRoot`) | `dsm::sofi::resolution::tests::an_orphaned_parent_voids_a_valid_route_and_never_invalidates_it` | Unreachable, same as 0206. |
| MR-DSM-0213 | Partial | `dsm::sofi::registration` (no owner-exclusive lock construct found) | no test found | Unreachable, same as 0206; no test isolates "any party can carry" specifically. |
| MR-DSM-0214 | Partial | `dsm::sofi::resolution::{RouteFacts, consumed_route L337, route_impossible L382}` | `dsm::sofi::resolution::tests::an_orphaned_parent_voids_a_valid_route_and_never_invalidates_it` (partial coverage) | Corrects vague first-pass locus (`sofi/`) to the actual multi-leg route-binding logic; still unreachable from production. No `SettlementBundle`-type construct found anywhere in `dsm/src/sofi` or the JNI bridge. |
| MR-DSM-0215 | Partial | `dsm::vault::fulfillment::FulfillmentMechanism::AmmConstantProduct` (fulfillment.rs:114-129, reachable via DLV); `dsm::sofi::arith` (checked integer resolution, dark) | no test found isolating byte-identical-route determinism | — |
| MR-DSM-0216 | Partial | `dsm::sofi::publication::{recognize_setup L203, recognize_fulfillment L250}` | `dsm::sofi::publication` tests exist (recognition/namespace tests) but none assert "visibility grants no priority" specifically | Unreachable, same as 0206. |
| MR-DSM-0217 | Missing | — | no test found | Confirmed: no "perpetual", "liquidation", or "funding_rate" code anywhere in `dsm/src`, `dsm_sdk/src`, or `proto/dsm_app.proto`. |
| MR-DSM-0218 | Partial | `dsm::sofi::*` (no wall-clock/height/duration reads; `CommitmentContext.step_index` pattern used throughout instead) | no test found | No wall-clock, height or duration read in `dsm::sofi`; no test asserts it. |
| MR-DSM-0219 | Partial | `dsm::sofi::*` (no offline-bearer integration found) | no test found | Same dark-module reachability gap as 0206; liveness-boundary claim not independently tested. |
| MR-DSM-0220 | Met | `proto/dsm_app.proto:1283` (`storage_set_id` field); `dsm_sdk::sdk::economic_admission_flow::canonical_set` (L83, network-derived); enforced at `dsm::economic::{provenance.rs:1199 ReleaseForeignSet, native_reserve.rs:462 ForeignSet, peer_lineage.rs:413}` | `dsm::economic::native_reserve::tests::a_release_must_succeed_exactly_its_parent` (asserts `ReleaseRefusal::ForeignSet`) | Three checkpoints refuse a caller-supplied or foreign `storage_set_id` against the network-canonical set: `provenance.rs` (`ReleaseForeignSet`), `native_reserve.rs` (`ForeignSet`), `peer_lineage.rs`. |
| MR-DSM-0221 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0222 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0223 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0224 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0225 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0226 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0227 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0228 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0229 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0230 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0231 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0232 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0233 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0234 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0235 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0236 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0237 | Deferred | — | — | DBTC, excluded this round (DSM-HL-064). |
| MR-DSM-0238 | Not code | — | — | Recovery dependency boundary (out of scope). |
| MR-DSM-0239 | Not code | — | — | Offline-bearer dependency boundary (out of scope). |
| MR-DSM-0240 | Partial | dsm · types/device_state.rs · `advance` (heads); economic/state.rs (sources) | no test found | Same missing general Σ as MR-DSM-0186. |
| MR-DSM-0241 | Partial | core modules collectively (hashing/SMT/encoding present; precommitment/guards/resource-derivation/shared-κres absent as an explicit mechanism) | no single test (theorem-level claim) | Hashing, SMT and canonical encoding exist; precommitment, guards, resource derivation and a shared κres do not. |
| MR-DSM-0242 | Met | `dsm::economic::register::{economic_root_register_key L58, RegisteredEconomicRoot L406}` | `...register::tests::a_registered_root_is_a_projection_of_a_verified_claim` | — |
| MR-DSM-0243 | Partial | dsm · types/device_state.rs · `advance` | `device_state::tests::advance_rejects_balance_underflow` | `advance` is the production door. `transition.rs::create_next_state` and `::apply_transition` are a second public path that produces state outside it (no production caller; used by `tools/vertical_validation`), §4.3. |
| MR-DSM-0244 | Partial | dsm · types/device_state.rs · `advance` | `device_state::tests::advance_rejects_balance_underflow` | Same second path as MR-DSM-0243. |
| MR-DSM-0245 | Partial | `dsm::core::state_machine::relationship::RelationshipManager` (per-pair independence; no shared-sequencer construct found anywhere) | no test found | Per-pair independence in `relationship.rs`; no shared sequencer. No test isolates the principle. |
| MR-DSM-0246 | Not code | — | — | Cryptographic safety assumption (collision resistance), not a testable code requirement; BLAKE3 itself is implemented (see 0259). |
| MR-DSM-0247 | Not code | — | — | Cryptographic safety assumption (unforgeability); SPHINCS+ itself is implemented (see 0259). |
| MR-DSM-0248 | Partial | `dsm::crypto::canonical_lp::write_lp` (canonical_lp.rs:23) | no test in `canonical_lp.rs`; exercised only indirectly by hash-preimage tests | — |
| MR-DSM-0249 | Met | `dsm::core::state_machine::relationship::RelationshipManager::get_relationship_key` (relationship.rs:450) | `dsm::core::state_machine::relationship::tests::test_relationship_manager` (order-independence asserted at L787) | — |
| MR-DSM-0250 | Partial | `dsm::economic::register::{economic_root_register_key L58, position_seed L74}`; `dsm::economic::keys.rs` | no test isolates the derivation; register.rs tests use the keys indirectly | — |
| MR-DSM-0251 | Partial | dsm · types/device_state.rs · `advance` (no guard-family or resource-key abstraction) | no test found | No guard-family or resource-key abstraction. |
| MR-DSM-0252 | Met | `dsm::merkle::sparse_merkle_tree::SparseMerkleTree::{get_inclusion_proof L258, verify_proof_against_root L342}` | `...sparse_merkle_tree::tests::verify_proof_against_root_static`; `...inclusion_proof_trailing_bytes_rejected` | — |
| MR-DSM-0253 | Partial | dsm · types/device_state.rs · `advance` (heads); economic/state.rs (sources) | no test found | Monotone only for relationship heads and economic sources. |
| MR-DSM-0254 | Not code | — | — | Blanket fidelity assumption over the whole predicate; not a single-code-site requirement. |
| MR-DSM-0255 | Not code | — | — | Offline/hardware dependency boundary (out of scope). |
| MR-DSM-0256 | Met | `dsm_storage_node::db::sqlite` (durable get/put functions, e.g. L1459 `get_object_by_key`); `dsm_storage_node::db::pg.rs` | `dsm_storage_node::tests::cells_keep_everything::a_second_value_at_a_key_is_kept_after_the_first_never_refused`; `dsm_storage_node::db::sqlite::tests::immutable_put_is_write_once_on_the_tuple` | — |
| MR-DSM-0257 | Met | `dsm::economic::native_reserve::{position_leader, resolve_successor}` built on `dsm::sofi::arith::resolve` | `dsm::economic::native_reserve::tests::finality_without_the_deterministic_leader_is_impossible` | The native ERA reserve path is production-reachable. |
| MR-DSM-0258 | Met | same `native_reserve`/`arith::resolve` (leader-unavailable ⇒ `Unresolved`/`Open`, never a fallback leader) | same test as 0257 | — |
| MR-DSM-0259 | Met | `dsm::crypto::{blake3.rs, sphincs.rs, kyber.rs}` | `dsm::crypto::sphincs::tests::sign_verify_each_variant`; `dsm::crypto::blake3::tests::domain_hash_includes_nul_terminator` | — |
| MR-DSM-0260 | Not code | `lean4/DSMGuardedTripwire.lean`, `lean4/DSMCardinality.lean` | — | Formal artifacts confirmed present. |
| MR-DSM-0261 | Not code | `tla/DSM_ProtocolCore.tla`, `tla/DSM_Abstract.tla` | — | Formal artifacts confirmed present. |
| MR-DSM-0262 | Not code | `tla/DSM_Abstract.tla` / `DSM_ProtocolCore.tla` | — | Formal artifact. |
| MR-DSM-0263 | Not code | `tla/DSM_SofiSuccessorCells.tla` | — | Confirmed present. |
| MR-DSM-0264 | Not code | `lean4/DSMRecognition.lean` | — | Confirmed present. |
| MR-DSM-0265 | Partial | `dsm::sofi::conformance::{derive_policy_fulfillments L173, check_fulfillment_against_precommit L271, fulfillment_conformance L366}` | conformance.rs has ~12 `#[test]`s | Module exists and is tested, but — like the rest of `sofi/` — is not reachable from production, so it does not currently discharge resource-key/injectivity obligations against a live path. |
| MR-DSM-0266 | Not code | — | — | Scope statement about a TLA model. |
| MR-DSM-0267 | Partial | `dsm::sofi::conformance` (same as 0265) | conformance.rs tests run in CI, but only against the dark `sofi` module | Conformance testing exists but doesn't yet tie a *production* implementation to the model, since SoFi has no production entry point (see 0187/0206). |
| MR-DSM-0268 | Partial | dsm · types/device_state.rs · `advance` | no test of the full step sequence | The pipeline exists for concrete mechanisms (transfer, DLV ops) but not as the generic Σ/guard-family/resource-key algorithm the requirement describes (zero matches for those terms in `transition.rs`). |
| MR-DSM-0269 | Met | `dsm::sofi::fisher_yates::first_member`; `dsm::economic::register::position_leader`; `dsm::economic::native_reserve` (live via ERA reserve release) | `dsm::economic::native_reserve::tests::finality_without_the_deterministic_leader_is_impossible` | — |
| MR-DSM-0270 | Partial | `dsm::storage_cell` (arrival-record/ByteCommit primitives, §14/§15); `dsm::sofi::arith::resolve` (live evaluator, pre-A6 quorum count) | `dsm::sofi::arith::tests::the_leaders_first_value_held_by_two_others_is_final` (tests the pre-A6 mechanism, not the A6 route-chain) | Confirmed: Amendment A6's three-link route-chain finality evaluator does not exist; `arith::resolve` (production path via `native_reserve`) still counts leader-copy quorum, and `storage_cell.rs`'s new arrival-record machinery (added in the immediately preceding commit) is not wired into any route-chain finality check. |
| MR-DSM-0271 | Partial | dsm_sdk · storage/client_db/b0x_consumed.rs; sdk/b0x_sdk.rs · `retrieve_from_b0x_v2`, `record_consumed_b0x` | `b0x_consumed::tests` (not yet run) | Added by Amendment A7. Built, not yet compiled or exercised end to end. |
| MR-DSM-0272 | Missing | — | — | Added by Amendment A7. No spool payload is encrypted (G16). |

### 8.2 SoFi settlement specification

| MR-ID | Status | Code (crate · file · function) | Test | Gap / note |
|---|---|---|---|---|
| MR-SOFI-0001 | Partial | dsm · sofi/validation.rs · `validate()`; not gated in device_state.rs::advance | `sofi/validation.rs::a_well_formed_swap_is_valid` | Predicate tested; unwired |
| MR-SOFI-0002 | Met | dsm_storage_node · api/cells.rs, api/objects/immutable.rs (no signing code) | `immutable_store_round_trip.rs::a_put_with_no_authorization_is_taken_on_the_served_assembly` | — |
| MR-SOFI-0003 | Partial | dsm_storage_node (no attestation code); dsm · sofi/arith.rs::`resolve` | no test found | No attestation code; no test. |
| MR-SOFI-0004 | Met | dsm_storage_node · api/cells.rs (generic KV, no role concept) | `cells_keep_everything.rs::only_malformed_requests_are_refused` | Test added |
| MR-SOFI-0005 | Met | dsm · sofi/derive.rs (pure fns of parent+op) | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | — |
| MR-SOFI-0006 | Met | dsm · sofi/signature.rs::`verify_operation`; device_state.rs::advance:1204 (live) | `sofi/signature.rs::a_setup_signs_its_own_digest`, `a_vault_creation_signs_the_operation` | — |
| MR-SOFI-0007 | Met | dsm · sofi/signature.rs (SPHINCS+ verify) | `sofi/signature.rs::a_second_valid_signature_over_one_body_is_the_same_object` | — |
| MR-SOFI-0008 | Met | dsm · sofi/wire/objects.rs::`TraderPrecommitBody` (L278) | `sofi/validation.rs::precommit_roots_that_do_not_match_the_cores_are_invalid` | — |
| MR-SOFI-0009 | Met | dsm · sofi/derive.rs | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | — |
| MR-SOFI-0010 | Met | dsm · sofi/derive.rs::`successor_attempt_key` | `sofi_v8_independent.rs::successor_attempt_keys_are_o1_and_distinct` | — |
| MR-SOFI-0011 | Met | dsm · sofi/derive.rs::`external_commitment_single/route` | `sofi_v8_vault_bytes.rs::the_e_form_follows_the_leg_count_for_one_two_and_three_legs` | — |
| MR-SOFI-0012 | Met | dsm · sofi/wire/objects.rs::`VaultStateLeaf` (L1225) | `sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips` | — |
| MR-SOFI-0013 | Partial | dsm · sofi/validation.rs::`validate` (unwired) | `sofi/validation.rs::a_pre_root_the_entries_do_not_produce_does_not_fold` | — |
| MR-SOFI-0014 | Met | dsm · sofi/derive.rs, wire/mod.rs | `sofi_v8_independent.rs::counters_are_checked_never_wrapped` | — |
| MR-SOFI-0015 | Met | dsm · sofi/derive.rs::`resolution_claim` | `sofi/registration.rs::registration_needs_both_cells_final_and_the_root_on_this_claim` | — |
| MR-SOFI-0016 | Met | dsm · sofi/arith.rs::`resolve`/`CellResolution` | `sofi/arith.rs::an_unreachable_leader_resolves_nothing_and_no_member_stands_in` | — |
| MR-SOFI-0017 | Partial | dsm · sofi/validation.rs::`validate`; device_state.rs::advance (sig-check only) | n/a in production | — |
| MR-SOFI-0018 | Partial | dsm · sofi/conformance.rs::`ConformanceEvidence` (Default is cfg(test)) | `sofi/conformance.rs::invalid_dominates_unavailable_in_item_order` | No production acquisition caller |
| MR-SOFI-0019 | Met | dsm · sofi/derive.rs, ccb/mod.rs | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | — |
| MR-SOFI-0020 | Partial | dsm · sofi/* (all modules, unused in production) | n/a | — |
| MR-SOFI-0021 | Partial | dsm_storage_node, dsm_sdk (no second validator found) | no test found | Absence claim, no test |
| MR-SOFI-0022 | Not code | tla/DSM_SofiSuccessorCells.tla; lean4/DSMSofiStorage.lean (both exist, verified) | n/a | Outside the 4 crates |
| MR-SOFI-0023 | Partial | dsm · sofi/validation.rs::`validate` | `sofi/validation.rs::an_off_by_one_output_is_invalid` | As 0017 |
| MR-SOFI-0024 | Met | dsm · crypto/blake3.rs::`dsm_domain_hasher`; common/domain_tags/dsm/misc/sofi.rs | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | — |
| MR-SOFI-0025 | Met | dsm · sofi/derive.rs::`h()` | `sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips` | — |
| MR-SOFI-0026 | Met | dsm · sofi/wire/mod.rs (BE grammar) | `sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips` | — |
| MR-SOFI-0027 | Met | dsm · ccb/mod.rs (class-keyed CCB) | `sofi_v8_independent.rs::class_discriminants_do_not_collide` | — |
| MR-SOFI-0028 | Met | dsm · sofi/wire/mod.rs::`next_position` | `sofi_v8_independent.rs::counters_are_checked_never_wrapped` | — |
| MR-SOFI-0029 | Met | dsm · sofi/conformance.rs::`Validation::and/all` | `sofi/conformance.rs::invalid_dominates_and_unavailable_never_becomes_invalid` | Behaviour conforms. Affected by the MR-SOFI-0030 fix (Unavailable moves out of the predicate type); the test must move with it. |
| MR-SOFI-0030 | Violated | dsm · sofi/conformance.rs · `Validation` (Valid \| Invalid \| Unavailable), `FulfillmentConformance`; sofi/validation.rs · `route_validation` | `sofi/validation.rs::missing_evidence_is_unavailable_never_invalid` | Reconciled Met → Violated (ChatGPT CG-02; Gemini agrees). Core's predicate type has `Unavailable` as a third value and folds it in conjunction; Amendment S3 makes Unavailable the network layer's fetch status, never a predicate value. Behaviour otherwise conforms: absent evidence is never read as Invalid. |
| MR-SOFI-0031 | Partial | dsm_sdk · sdk/sofi_evidence.rs (no production caller) | none found | — |
| MR-SOFI-0032 | Partial | dsm_sdk · sdk/sofi_advance.rs:702 (`Resolution::Void`, dark) | none found | §9.1 challenge absent |
| MR-SOFI-0033 | Partial | dsm · sofi/validation.rs::`validate`; device_state.rs::advance | as 0017 | — |
| MR-SOFI-0034 | Met | dsm_storage_node · api/cells.rs, objects/immutable.rs | `immutable_store_round_trip.rs::a_put_with_no_authorization_is_taken_on_the_served_assembly` | — |
| MR-SOFI-0035 | Met | dsm · sofi/storage.rs::`StoredFact`; arith.rs | `sofi/storage.rs::wrong_bytes_never_count` | — |
| MR-SOFI-0036 | Violated | dsm · types/device_state.rs::advance:1198-1205 (matches!+dispatches on 3 SoFi ops); core/state_machine/relationship.rs::`validate_against_forward_commitment`:275-277 (names `Operation::SofiSetup/SofiVaultCreate/SofiFulfill`) | n/a | `core/state_machine/relationship.rs` names `SofiSetup`, `SofiVaultCreate` and `SofiFulfill`, and `DeviceState::advance` dispatches them into `sofi::signature`. |
| MR-SOFI-0037 | Partial | dsm_sdk · sdk/sofi_sdk.rs (Produced/ToPublish, unreachable) | `sofi_sdk.rs::a_producer_refuses_a_route_that_does_not_chain` | — |
| MR-SOFI-0038 | Partial | dsm_storage_node · api/objects/immutable.rs | `immutable_store_round_trip.rs::bytes_put_into_the_immutable_store_come_back_byte_identical` | The suite runs on Postgres since the SQLite backend was deleted (2026-09-24). |
| MR-SOFI-0039 | Met | dsm_storage_node/src (zero SoFi refs, verified by grep) | `cells_keep_everything.rs::only_malformed_requests_are_refused` | — |
| MR-SOFI-0040 | Met | dsm · sofi/{arith,storage,registration,conformance}.rs (distinct enums) | `sofi/registration.rs::registration_needs_both_cells_final_and_the_root_on_this_claim` | — |
| MR-SOFI-0041 | Partial | dsm · sofi/publication.rs::`Publication::Precommit` (P is inert bare data) | no test found | Absence claim, untested |
| MR-SOFI-0042 | Met | dsm · sofi/wire/objects.rs::`DlvPolicyFulfillmentBody` (0x0038, no issuer field) | `sofi/signature.rs::an_unsupported_body_class_is_refused_at_both_ends` | — |
| MR-SOFI-0043 | Met | dsm · sofi/signature.rs::`verify_fulfillment` | `sofi/signature.rs::a_fulfillment_signs_its_own_digest` | — |
| MR-SOFI-0044 | Met | dsm · sofi/registration.rs::`fulfillment_registered` | `sofi/registration.rs::registration_needs_both_cells_final_and_the_root_on_this_claim` | — |
| MR-SOFI-0045 | Met | dsm · sofi/storage.rs::`StoredFact` | `sofi/storage.rs::stored_returns_exact_bytes` | — |
| MR-SOFI-0046 | Partial | dsm_sdk · sdk/core_sdk.rs::`apply_incoming_transfer_staged` (production generic bilateral apply); SoFi instance dark | none cited | The production function is `apply_incoming_transfer_staged` (`apply_incoming_transfer_full_state` is test-only). The SoFi instance of the pattern has no production entry. |
| MR-SOFI-0047 | Partial | dsm · sofi/* (no approval code anywhere) | n/a | — |
| MR-SOFI-0048 | Partial | dsm · sofi/validation.rs::`route_validation` | `sofi/validation.rs::a_well_formed_swap_is_valid` | As 0017 |
| MR-SOFI-0049 | Met | dsm · sofi/signature.rs; device_state.rs::advance (live) | `sofi/signature.rs::a_precommit_signs_its_own_digest` | — |
| MR-SOFI-0050 | Partial | dsm · sofi/wire/objects.rs (SettlementBody::Swap/Close, 3 Operation variants) | `sofi_v8_vault_bytes.rs::both_settlement_branches_and_both_authorities_match_and_round_trip` | — |
| MR-SOFI-0051 | Partial | dsm · sofi/derive.rs::`canonical_legs`/`external_commitment_route` | `sofi_v8_vault_bytes.rs::the_e_form_follows_the_leg_count_for_one_two_and_three_legs` | — |
| MR-SOFI-0052 | Not code | n/a | n/a | Fault-model assumption used by the safety proof; nothing to implement. |
| MR-SOFI-0053 | Not code | n/a | n/a | Same as 0052 |
| MR-SOFI-0054 | Met | dsm · sofi/storage.rs::`stored()`; dsm_storage_node · api/objects/immutable.rs:140-148,177-187 (hash-on-read) | `sofi/storage.rs::wrong_bytes_never_count` | The node-side corruption path is untested. |
| MR-SOFI-0055 | Met | dsm · sofi/{signature,storage,publication}.rs (every check re-verifies) | `sofi/signature.rs::a_body_cannot_name_its_own_signer` | — |
| MR-SOFI-0056 | Partial | dsm · sofi/{signature,conformance,validation}.rs (pure/sync, no timers) | no test specifically asserts this | **corrected from Met**: no test would catch a timing dependency being introduced |
| MR-SOFI-0057 | Not code | n/a | n/a | — |
| MR-SOFI-0058 | Not code | n/a | n/a | Eventual-reachability assumption; nothing to implement. |
| MR-SOFI-0059 | Not code | n/a | n/a | — |
| MR-SOFI-0060 | Not code | n/a | n/a | — |
| MR-SOFI-0061 | Partial | dsm_sdk · sdk/sofi_advance.rs (Void exists, dark) | none found | §9.1 challenge absent |
| MR-SOFI-0062 | Not code | n/a | n/a | — |
| MR-SOFI-0063 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::an_unreachable_leader_resolves_nothing_and_no_member_stands_in` | — |
| MR-SOFI-0064 | Met | dsm · sofi/conformance.rs (item 5) | `sofi/conformance.rs::item_5_an_earlier_attempt_must_have_a_permanent_storage_resolution` | — |
| MR-SOFI-0065 | Partial | dsm · sofi/wire/objects.rs (no lock field); sdk/sofi_advance.rs (dark) | no test found | **corrected from Met**: no test asserts absence of a prepare-lock |
| MR-SOFI-0066 | Met | dsm · sofi/wire/mod.rs::`next_position`/`next_attempt` | `sofi_v8_independent.rs::counters_are_checked_never_wrapped` | — |
| MR-SOFI-0067 | Met | dsm · sofi/wire/mod.rs:174-177 (constants); wire/objects.rs::`VaultStateLeaf` | `sofi_v8_independent.rs::bounds_are_the_ruled_values` | — |
| MR-SOFI-0068 | Partial | dsm · economic/register.rs::`RootRegisterProfile::verify_candidate`:126-161; ccb/mod.rs::`storage_set_id`:830 | no test found | No test found. Spec amended to match the code (Amendment S6, owner 2026-09-23); the finding that the id also covered incarnations (ChatGPT CG-05) is closed by that amendment. |
| MR-SOFI-0069 | Partial | dsm · sofi/wire/objects.rs::`VaultStateLeaf` (storage_set_id never mutated by any vault-state transform) | no dedicated test found | `storage_set_id` is never mutated by a vault-state transform; no test asserts membership stays frozen (the `validation.rs` scope test checks `NetworkScopeMismatch`, a different property). |
| MR-SOFI-0070 | Met | dsm · route_chain.rs::`Route::leader` (attempt cells, sofi/exercise.rs); economic/register.rs::`position_leader` | `sofi/exercise.rs::an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s` | — |
| MR-SOFI-0071 | Met | dsm · route_chain.rs `Route::of` (seed and committed set only; availability never enters) | `route_chain.rs::a_cell_is_routed_only_over_the_committed_set`; `a_route_needs_exactly_five_members` | — |
| MR-SOFI-0072 | Met | dsm · sofi/fisher_yates.rs::`permute` | `sofi/fisher_yates.rs::empty_and_duplicate_views_are_refused` | — |
| MR-SOFI-0073 | Met | dsm · sofi/fisher_yates.rs::`permute` (descending loop) | `sofi_v8_independent.rs::fisher_yates_matches_the_independent_algorithm_and_the_frozen_order` | — |
| MR-SOFI-0074 | Met | dsm · sofi/fisher_yates.rs::`uniform_draw` | `sofi_v8_independent.rs::fisher_yates_matches_the_independent_algorithm_and_the_frozen_order` | — |
| MR-SOFI-0075 | Partial | dsm · sofi/fisher_yates.rs::`uniform_draw` (ctr: u32, checked_add) | none — exhausting 2^32 draws is impractical to test | **corrected from Met**: overflow branch is unreachable in any realistic test |
| MR-SOFI-0076 | Met | dsm · sofi/fisher_yates.rs::`first_member` | `sofi/exercise.rs::an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s` | — |
| MR-SOFI-0077 | Met | dsm · sofi/derive.rs::`storage_seed` | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | — |
| MR-SOFI-0078 | Partial | dsm · economic/register.rs::`position_seed` | no test found | No test for `position_seed`. |
| MR-SOFI-0079 | Met | dsm · route_chain.rs `Route::leader`; economic/register.rs::`position_leader` | `sofi/exercise.rs::an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s` | — |
| MR-SOFI-0080 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::the_leaders_first_value_held_by_two_others_is_final` | — |
| MR-SOFI-0081 | Partial | dsm · sofi/arith.rs (copy-count model, no route-chain writes) | n/a — S4 mechanism doesn't exist | — |
| MR-SOFI-0082 | Partial | dsm · sofi/arith.rs::`resolve` (count model, order-independent) | `sofi/arith.rs::copies_count_wherever_the_value_sits_in_a_copys_list` | Tests the pre-S4 model, not the chain rule |
| MR-SOFI-0083 | Met | dsm_storage_node · api/cells.rs::`append_index`/`put_cell` | `immutable_store_round_trip.rs::a_put_with_no_authorization_is_taken_on_the_served_assembly` | — |
| MR-SOFI-0084 | Met | dsm · sofi/arith.rs::`resolve`/`resolve_objects` | `sofi/arith.rs::the_adapter_derives_final_from_the_recognized_view` | — |
| MR-SOFI-0085 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::a_later_value_at_the_leader_never_becomes_final` | — |
| MR-SOFI-0086 | Partial | dsm · sofi/arith.rs::`resolve` (singular by construction) | no test explicitly asserts "at most one" | **corrected from Met**: no negative test demonstrates two finals is impossible |
| MR-SOFI-0087 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::a_later_value_at_the_leader_never_becomes_final` | — |
| MR-SOFI-0088 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::leader_held_settles_the_race_before_finality` | — |
| MR-SOFI-0089 | Met | dsm · sofi/arith.rs::`resolve` | `sofi/arith.rs::an_unreachable_leader_resolves_nothing_and_no_member_stands_in` | — |
| MR-SOFI-0090 | Met | dsm_storage_node · api/cells.rs::`put_cell`/`get_cell` | `cells_keep_everything.rs::a_second_value_at_a_key_is_kept_after_the_first_never_refused` | — |
| MR-SOFI-0091 | Met | dsm_storage_node · api/cells.rs (no auth check) | `immutable_store_round_trip.rs::a_put_with_no_authorization_is_taken_on_the_served_assembly` | — |
| MR-SOFI-0092 | Partial | dsm_storage_node · api/cells.rs::`put_cells`:146 (generic atomic batch) | `cells_keep_everything.rs::a_batch_put_takes_every_key_or_none_on_the_served_assembly` | SDK-side K_ful/K_root pairing unconfirmed (dark) |
| MR-SOFI-0093 | Partial | dsm · sofi/publication.rs::`Publication::address`; dsm_storage_node · objects/immutable.rs::`put_immutable` | `immutable_store_round_trip.rs::bytes_put_into_the_immutable_store_come_back_byte_identical` | The suite runs on Postgres since the SQLite backend was deleted (2026-09-24). |
| MR-SOFI-0094 | Met | dsm · sofi/storage.rs::`stored()` | `sofi/storage.rs::two_members_is_not_stored` | — |
| MR-SOFI-0095 | Met | dsm · sofi/publication.rs::`Publication::locators` | `sofi/publication.rs::every_kind_is_recognized_under_the_locator_it_is_indexed_under` | — |
| MR-SOFI-0096 | Met | dsm_storage_node · api/cells.rs::`append_index`/`read_index` | `cells_keep_everything.rs::an_index_pages_in_append_order_from_the_last_seq` | — |
| MR-SOFI-0097 | Met | dsm · sofi/storage.rs::`keep_verifying`/`keep_all_verifying` | `sofi/storage.rs::over_budget_is_unavailable_never_none` | Behaviour conforms. Affected by the MR-SOFI-0030 fix. |
| MR-SOFI-0098 | Met | dsm_storage_node · api/cells.rs::`put_cell` | `cells_keep_everything.rs::a_second_value_at_a_key_is_kept_after_the_first_never_refused` | — |
| MR-SOFI-0099 | Met | dsm_storage_node · api/cells.rs::`get_cell` (no signature field) | `cells_keep_everything.rs::a_key_nothing_was_put_under_reads_as_an_empty_list_with_200` | — |
| MR-SOFI-0100 | Met | dsm_storage_node · api/objects/immutable.rs, api/cells.rs (content-blind) | `cells_keep_everything.rs::only_malformed_requests_are_refused` | — |
| MR-SOFI-0101 | Met | dsm · sofi/arith.rs (LeaderHeld/Final); sofi/storage.rs (Stored) | (compound of arith.rs + storage.rs tests above) | — |
| MR-SOFI-0102 | Met | dsm · sofi/{registration,storage,arith,exercise}.rs | `sofi/exercise.rs::a_successor_key_resolves_to_the_e_of_the_exercise_that_names_it_or_stays_open` | — |
| MR-SOFI-0103 | Met | dsm · common/domain_tags/dsm/misc/sofi.rs | `sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests` | Wrong tag string would break golden hashes |
| MR-SOFI-0104 | Met | dsm · common/domain_tags/dsm/misc/sofi.rs (reserved tags) | `common/domain_tags/mod.rs::all_tags_are_unique` | — |
| MR-SOFI-0105 | Partial | dsm · common/domain_tags/dsm/misc/sofi.rs (tag simply absent, no registry) | no test found | **corrected from "conformant"**: unlike CCB class numbers, domain tags have no `burned_class`-equivalent test preventing reintroduction of a retired string |
| MR-SOFI-0106 | Met | dsm · ccb/mod.rs::`class`/`burned_class` | `sofi_v8_independent.rs::class_discriminants_do_not_collide` | — |
| MR-SOFI-0107 | Met | dsm · ccb/mod.rs::`burned_class`:341-347 | `sofi_v8_independent.rs::class_discriminants_do_not_collide` | — |
| MR-SOFI-0108 | Met | dsm · ccb/mod.rs (OwnerAuthorityDsmSuccessor); sofi/admission.rs::`admissible` | `sofi/admission.rs::beta_refuses_the_reserved_owner_authority` | — |
| MR-SOFI-0109 | Met | dsm · sofi/wire/objects.rs::`SignedSofiObject`:638 | `sofi_v8_independent.rs::the_signed_envelope_matches_the_independent_encoder` | — |
| MR-SOFI-0110 | Met | dsm · sofi/derive.rs (id over body); sofi/signature.rs | `sofi/signature.rs::a_second_valid_signature_over_one_body_is_the_same_object` | — |
| MR-SOFI-0111 | Met | dsm · crypto/sphincs.rs · sphincs_sign (deterministic R=H(sk_prf‖m), L891) | sofi/signature.rs::tests::a_second_valid_signature_over_one_body_is_the_same_object | — |
| MR-SOFI-0112 | Met | dsm · sofi/derive.rs · vault_id | tests/sofi_v8_independent.rs::derivations_match_the_independent_hasher_and_the_frozen_golden_digests | Golden vector + independent hasher |
| MR-SOFI-0113 | Met | dsm · sofi/derive.rs · vault_state_key/vault_state_leaf_value/vault_relationship_leaf_value | same golden-vector test | — |
| MR-SOFI-0114 | Met | dsm · sofi/derive.rs · route_digest | same golden-vector test | — |
| MR-SOFI-0115 | Met | dsm · sofi/derive.rs · vault_genesis_locator/relationship_key | same golden-vector test | — |
| MR-SOFI-0116 | Met | dsm · sofi/derive.rs · setup_id | same golden-vector test | — |
| MR-SOFI-0117 | Met | dsm · sofi/derive.rs · relationship_leaf_genesis/relationship_leaf_next | same golden-vector test | — |
| MR-SOFI-0118 | Met | dsm · sofi/derive.rs · relationship_index_key | same golden-vector test | — |
| MR-SOFI-0119 | Met | dsm · sofi/derive.rs · setup_ref/setup_signing_digest | same golden-vector test | — |
| MR-SOFI-0120 | Met | dsm · economic/claim_envelope.rs · economic_root_claim_envelope_digest (L216-222); sofi/derive.rs::claim_ref | golden-vector test asserts claim_ref == indep hash | — |
| MR-SOFI-0121 | Met | dsm · sofi/derive.rs · precommit_id/precommit_signing_digest | golden-vector test | — |
| MR-SOFI-0122 | Met | dsm · sofi/wire/objects.rs · DlvPolicyFulfillmentBody (no proof field) | tests/sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0123 | Met | dsm · sofi/derive.rs · fulfillment_id/fulfillment_signing_digest | golden-vector test | — |
| MR-SOFI-0124 | Met | dsm · sofi/derive.rs · fulfillment_register_key | golden-vector test | — |
| MR-SOFI-0125 | Met | dsm · sofi/derive.rs · resolution_claim | golden-vector test (via C_q fields) | — |
| MR-SOFI-0126 | Met | dsm · economic/register.rs · economic_root_register_key | dsm/tests/economic_lineage_register.rs (key-uniqueness assertions) | — |
| MR-SOFI-0127 | Met | dsm · sofi/derive.rs · successor_base_key | golden-vector test | — |
| MR-SOFI-0128 | Met | dsm · sofi/derive.rs · successor_attempt_key | golden-vector test; sofi_v8_independent.rs::successor_attempt_keys_are_o1_and_distinct | — |
| MR-SOFI-0129 | Met | dsm · sofi/derive.rs · trader_core_digest/dlv_core_digest/settlement_core_digest | golden-vector test | — |
| MR-SOFI-0130 | Met | dsm · sofi/derive.rs · external_commitment_single | golden-vector test | — |
| MR-SOFI-0131 | Met | dsm · sofi/derive.rs · external_commitment_route/route_leg_set_digest | golden-vector test | — |
| MR-SOFI-0132 | Met | dsm · sofi/derive.rs · external_commitment_single/route (arg lists) | golden-vector test (by construction — no such params exist) | — |
| MR-SOFI-0133 | Met | dsm · economic/write_set.rs · build_write_set SofiSetup arm (L754-780, insert-only from zero) | economic/write_set.rs::tests (insert-only refusal path); sofi/conformance.rs item_6 tests | — |
| MR-SOFI-0134 | Met | dsm · sofi/derive.rs::setup_ref; sofi/signature.rs::SignedSofiBody::object_id | sofi/signature.rs::tests::a_second_valid_signature_over_one_body_is_the_same_object | — |
| MR-SOFI-0135 | Partial | dsm · economic/lineage.rs::advance_validated (SofiSetup arm, L718-740) | none for the deferral itself | Confirmed: comment at L714-717 states ClaimRef_p at p is explicitly deferred to "E2"; claim_ref is never checked against the registered claim on this path |
| MR-SOFI-0136 | Partial | dsm · sofi/validation.rs::Evidence struct (L236-243); validate() | sofi/validation.rs test suite (does not exercise SetupRegistered) | Confirmed: Evidence has objects/trader_leaves/vault_leaves only — no setup field; validate() never checks SetupRegistered |
| MR-SOFI-0137 | Met | dsm · sofi/conformance.rs::fulfillment_conformance item 6 (L435-475) | sofi/conformance.rs::tests::item_6_setup_registered_holds_for_every_leg | — |
| MR-SOFI-0138 | Met | dsm · sofi/validation.rs::trader_fold_entries/dlv_fold_entries (L975-1092) | sofi/validation.rs::tests::a_wrong_relationship_base_is_invalid; vault_post_states_are_recomputed_and_bound_to_the_stated_values | — |
| MR-SOFI-0139 | Met | dsm · sofi/signature.rs (verify_setup/verify_precommit/verify_fulfillment); wire/objects.rs G (no issuer field) | sofi/signature.rs::tests (whole module) | — |
| MR-SOFI-0140 | Met | dsm · sofi/derive.rs (module structure: stages only depend forward) | golden-vector test | — |
| MR-SOFI-0141 | Met | dsm · sofi/wire/objects.rs::TraderPrecommitBody | sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0142 | Met | dsm · sofi/registration.rs (P never writes K_root); economic/write_set.rs (no Precommit write-set arm) | economic/write_set.rs classification tests (fulfillment-only path) | — |
| MR-SOFI-0143 | Met | dsm · sofi/validation.rs::validate (CoreIdentityMismatch, L712-717) | sofi/validation.rs::tests::precommit_roots_that_do_not_match_the_cores_are_invalid | — |
| MR-SOFI-0144 | Partial | dsm_sdk · sdk/sofi_advance.rs (own_parent_claim / advance flow, L637-653) | dsm_sdk sofi_advance.rs test module (advance flow tests) | The parent-claim check lives in the `sofi_advance` SDK path. SoFi has no production entry (§3 G1); this obligation has to happen in the running system, and its only implementation is unreachable. |
| MR-SOFI-0145 | Met | dsm_sdk · sdk/sofi_advance.rs::final_root_cell (raw multi-member reads, L642-649) | dsm_sdk sofi_advance.rs tests | — |
| MR-SOFI-0146 | Met | dsm · sofi/validation.rs (L712-723); sofi/lineage.rs::descendant_fence | sofi/lineage.rs::tests::a_resolved_predecessor_admits_only_the_root_it_selected; nothing_descends_from_an_unresolved_conditional_predecessor | — |
| MR-SOFI-0147 | Met | dsm · sofi/validation.rs::validate (recompute_e check, L700-709) | sofi/validation.rs::tests::a_preimage_e_does_not_commit_to_is_invalid | — |
| MR-SOFI-0148 | Met | dsm · sofi/validation.rs (legs vs SwapIntent/hops, L1271-1290) | sofi/validation.rs::tests::a_missing_trader_movement_is_invalid / an_unchained_hop_is_invalid | — |
| MR-SOFI-0149 | Met | dsm · sofi/validation.rs::validate_swap/validate_close (fold + require realize/void root) | sofi/validation.rs::tests::trader_post_states_are_recomputed_and_bound_to_the_stated_values | — |
| MR-SOFI-0150 | Met | dsm · sofi/validation.rs (NetworkScopeMismatch, L1323-1326,1471-1474) | sofi/validation.rs::tests::a_vault_in_another_storage_set_is_invalid | — |
| MR-SOFI-0151 | Met | dsm · sofi/signature.rs::signer_key (caller-proven signer binding) | sofi/signature.rs::tests::a_body_cannot_name_its_own_signer | — |
| MR-SOFI-0152 | Met | dsm · sofi/lineage.rs::descendant_fence | sofi/lineage.rs::tests::nothing_descends_from_an_unresolved_conditional_predecessor | Wired but currently inert per own doc comment (writer never emits conditional rows yet) |
| MR-SOFI-0153 | Met | dsm · sofi/conformance.rs::derive_policy_fulfillments | sofi/conformance.rs::tests::item_3_the_policy_fulfillment_set_is_the_canonical_set_of_p | — |
| MR-SOFI-0154 | Met | dsm · sofi/conformance.rs::derive_policy_fulfillments (pure fn of P leg + shadow) | same | — |
| MR-SOFI-0155 | Partial | dsm · sofi/wire (G carries no lock semantics; DLV parent stays consumable) | no test found | G carries no lock field. No test asserts it. |
| MR-SOFI-0156 | Met | dsm · sofi/wire/objects.rs (G unsigned, no issuer field); sofi/validation.rs | sofi/signature.rs::tests::an_unsupported_body_class_is_refused_at_both_ends (G cannot be signed) | — |
| MR-SOFI-0157 | Partial | dsm · sofi/validation.rs::validate (no canonicality/liveness read anywhere) | no test found | `validate` reads no canonicality or liveness fact. No test asserts it. |
| MR-SOFI-0158 | Missing | dsm · sofi/wire/objects.rs::PolicyFulfillmentAuxRef (struct only, L1079-1091) | tests/sofi_v8_independent.rs (round-trip only, no candidate mechanism) | Confirmed: no producer/consumer anywhere in conformance.rs/validation.rs |
| MR-SOFI-0159 | Missing | none | none | As 0158 |
| MR-SOFI-0160 | Missing | none | none | As 0158 |
| MR-SOFI-0161 | Missing | none | none | As 0158 |
| MR-SOFI-0162 | Missing | none (grep confirms no MAX_POLICY_FULFILLMENT_AUX_CANDIDATES anywhere) | none | Confirmed absent |
| MR-SOFI-0163 | Missing | dsm · sofi/wire/mod.rs::MAX_VALIDATION_FETCH_BYTES (L222, declared only) | tests/sofi_v8_independent.rs::bounds_are_the_ruled_values (asserts the constant's value only) | Confirmed: grep shows zero enforcement use; only a value-equality assertion |
| MR-SOFI-0164 | Met | dsm · sofi/wire/objects.rs::TraderFulfillmentBody | sofi_v8_independent.rs::every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0165 | Partial | dsm_sdk · sdk/sofi_register.rs (leader-first batch write, L257-296) | dsm_sdk sofi_register.rs tests | The leader-first paired write lives in `sofi_register`. SoFi has no production entry (§3 G1); this obligation has to happen in the running system, and its only implementation is unreachable. |
| MR-SOFI-0166 | Met | dsm_storage_node (no SoFi-aware code at all — grep confirms zero hits) | dsm_storage_node/tests/cells_keep_everything.rs::a_second_value_at_a_key_is_kept_after_the_first_never_refused; ::only_malformed_requests_are_refused | Confirmed with a specific generic test, not just file-level absence |
| MR-SOFI-0167 | Met | dsm · sofi/derive.rs::resolution_claim; sofi/registration.rs (L118-124) | sofi/registration.rs::tests::registration_needs_both_cells_final_and_the_root_on_this_claim | — |
| MR-SOFI-0168 | Met | dsm · sofi/registration.rs::fulfillment_registered | sofi/registration.rs::tests::registration_needs_both_cells_final_and_the_root_on_this_claim | — |
| MR-SOFI-0169 | Met | dsm · sofi/registration.rs (Final adapter, first-writer-wins) | same test | — |
| MR-SOFI-0170 | Met | dsm · sofi/wire/objects.rs::SofiExercise; sofi/exercise.rs::recognize_exercise | sofi/exercise.rs::tests::an_exercise_round_trips_and_rebuilds_into_bound_objects | — |
| MR-SOFI-0171 | Met | dsm · sofi/exercise.rs::exercise_names_key/attempt_resolution | sofi/exercise.rs::tests::an_exercise_names_exactly_the_keys_its_fulfillment_and_precommit_name; a_successor_key_resolves_to_the_e_of_the_exercise_that_names_it_or_stays_open | — |
| MR-SOFI-0172 | Met | dsm · sofi/wire/objects.rs::SettlementPreimage (strict decode, L2095-2121) | sofi_v8_independent.rs::decoders_refuse_wrong_envelopes_truncation_and_trailing_bytes | — |
| MR-SOFI-0173 | Met | dsm · sofi/wire/objects.rs::SettlementBody::Swap fields | every_union_variant_round_trips | — |
| MR-SOFI-0174 | Met | dsm · sofi/wire/objects.rs::SettlementBody::Close fields | every_union_variant_round_trips | — |
| MR-SOFI-0175 | Met | dsm · sofi/wire/objects.rs::ValidationRef (E-independent variants, L997-995) | sofi_v8_independent.rs::closure_index_enforces_bounds_order_and_current_e_exclusion | — |
| MR-SOFI-0176 | Violated | dsm · sofi/wire/objects.rs::CLOSURE_FORBIDDEN_CONTENT_CLASSES (L1006-1021) | sofi_v8_independent.rs::closure_index_enforces_bounds_order_and_current_e_exclusion (only checks the classes already in the list) | Confirmed by grep: SOFI_SETTLEMENT_SWAP, SOFI_SETTLEMENT_CLOSE, SOFI_TRADER_CORE, SOFI_DLV_CORE, SOFI_SETTLEMENT_PREIMAGE are absent from the list; the existing test cannot catch this since it only iterates over the (incomplete) list itself |
| MR-SOFI-0177 | Met | dsm · sofi/conformance.rs (P/G-set/aux/F/Cq are validation inputs, never derive.rs::external_commitment_* args) | golden-vector test (by construction) | — |
| MR-SOFI-0178 | Met | dsm · sofi/derive.rs::recompute_e (branch selects form by leg count, L383-415) | sofi/conformance.rs rig (2-leg uses route form); dsm/tests fixtures (1-leg Close/Swap use single form) | — |
| MR-SOFI-0179 | Met | dsm · sofi/validation.rs::trader_fold_entries/dlv_fold_entries (BindExt effect, L1000-1082) | sofi/validation.rs::tests::a_wrong_relationship_base_is_invalid | — |
| MR-SOFI-0180 | Partial | dsm · sofi/wire/mod.rs::MAX_CLOSURE_OBJECT_BYTES/MAX_AUTH_ENVELOPES/MAX_VALIDATION_FETCH_BYTES/MAX_PROVENANCE_FANOUT (L212-227); only MAX_CLOSURE_REFS (validation.rs L688-697) and preimage byte bound (validation.rs L692) enforced as Invalid | sofi_v8_independent.rs::bounds_are_the_ruled_values (value-only, not enforcement) | Confirmed by grep: 4 of the 6 declared bounds are never read outside their own declaration and this test |
| MR-SOFI-0181 | Met | dsm · sofi/wire/objects.rs::VaultStateLeaf | every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0182 | Met | dsm · sofi/wire/objects.rs::VaultRelationshipLeaf/TraderRelationshipLeaf | every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0183 | Met | dsm · economic/write_set.rs (SofiSetup arm, insert-from-zero, L754-780) | economic/write_set.rs tests (WrongWriteSet on double-insert) | — |
| MR-SOFI-0184 | Met | dsm · sofi/wire/objects.rs::VaultStateLeaf (no vault_id/parent-root field) | every_object_matches_the_independent_encoder_and_round_trips | — |
| MR-SOFI-0185 | Met | dsm · sofi/validation.rs::swap_vault_post (fee stays in reserve_in, L1152-1188) | sofi/validation.rs::tests::a_close_pays_the_reserves_exactly_and_never_prices_them | — |
| MR-SOFI-0186 | Met | dsm · sofi/smt/fold.rs::batch_fold/verify_batch | sofi/smt/fold.rs::tests::the_batch_fold_equals_the_reference_tree_for_every_entry_mix (proptest) | — |
| MR-SOFI-0187 | Met | dsm · sofi/validation.rs::check_vault_write_set/check_trader_balances (exact entry set) | sofi/validation.rs::tests::an_extra_trader_entry_is_invalid; a_missing_trader_movement_is_invalid | — |
| MR-SOFI-0188 | Met | dsm · sofi/validation.rs::validate_swap | sofi/validation.rs::tests::a_well_formed_swap_is_valid; a_two_hop_route_chains_through_the_intermediate_token | — |
| MR-SOFI-0189 | Met | dsm · sofi/validation.rs::validate_close | sofi/validation.rs::tests::a_well_formed_close_by_the_origin_owner_is_valid; a_close_that_does_not_retire_the_vault_is_invalid | — |
| MR-SOFI-0190 | Met | dsm · sofi/wire/objects.rs codec (unbounded legs, byte-bound only) | sofi_v8_independent.rs::precommit_legs_and_route_leg_sets_are_canonical | — |
| MR-SOFI-0191 | Met | dsm · sofi/admission.rs::admissible (ROUTE_MAX_LEGS=2, admission-only) | sofi/admission.rs::tests::beta_refuses_more_hops_than_it_executes | — |
| MR-SOFI-0192 | Met | dsm · sofi/wire/objects.rs (strictly-ascending vault ids via check_strictly_ascending) | sofi_v8_independent.rs::precommit_legs_and_route_leg_sets_are_canonical | — |
| MR-SOFI-0193 | Met | dsm · dlv/route_commit.rs::constant_product_output_classified; sofi/validation.rs::validate_swap | sofi/validation.rs::tests::an_off_by_one_output_is_invalid; an_overflowing_reserve_is_invalid | — |
| MR-SOFI-0194 | Met | dsm · sofi/validation.rs::validate_close | sofi/validation.rs::tests::a_close_claiming_the_wrong_reserves_is_invalid; a_close_against_another_release_policy_is_invalid | — |
| MR-SOFI-0195 | Met | dsm · sofi/lineage.rs::advance_resolved | sofi/lineage.rs::tests::a_realized_position_installs_the_realize_root; a_void_position_installs_the_previous_root | — |
| MR-SOFI-0196 | Met | dsm · economic/credit.rs::CreditSource (4 arms, no SoFi arm); economic/peer_lineage.rs::validate_peer_lineage | economic/peer_lineage.rs::tests::a_conditional_peer_position_is_unresolved_and_never_invalid; no_validated_root_is_minted_from_either_branch_of_an_unresolved_claim | Cite the actual peer_lineage tests, not just "no arm exists" |
| MR-SOFI-0197 | Met | dsm · sofi/lineage.rs::advance_resolved | sofi/lineage.rs::tests::advance_is_refused_on_each_missing_conjunct | — |
| MR-SOFI-0198 | Met | dsm · sofi/validation.rs::validate_close (owner authority, L1452-1474); sofi/signature.rs | sofi/validation.rs::tests::a_close_of_another_owners_vault_is_invalid_on_identity_alone | — |
| MR-SOFI-0199 | Met | dsm · sofi/validation.rs (OwnerAuthorityNotActivated, L1441-1446); sofi/admission.rs | sofi/validation.rs::tests::a_close_naming_the_reserved_dsm_successor_is_invalid_not_unavailable | — |
| MR-SOFI-0200 | Met | dsm · economic/write_set.rs::build_write_set SofiVaultCreate arm (L782-817) | economic/write_set.rs::vault_create_binding_tests::a_creation_whose_every_binding_holds_produces_the_write_set | — |
| MR-SOFI-0201 | Partial | dsm_sdk · sdk/sofi_evidence.rs::fetch_vault_genesis (L127-151, structural decode + vault_id recompute only); dsm · economic/write_set.rs (market/amount/root checks only) | economic/write_set.rs::vault_create_binding_tests (covers root/amount/position/market checks) | Confirmed: no check that generation==0, status==Active, no relationship leaves, storage_set pinned to network set |
| MR-SOFI-0202 | Met | dsm_sdk · sdk/sofi_evidence.rs::fetch_vault_genesis (structural recognition only) | dsm_sdk sofi_evidence.rs test module | — |
| MR-SOFI-0203 | Met | dsm · sofi/validation.rs (no owner special-case in validate_swap) | sofi/validation.rs test suite (no owner-check branch in swap path) | — |
| MR-SOFI-0204 | Met | dsm · sofi/validation.rs::validate (RouteValidation); sofi/conformance.rs::fulfillment_conformance (independent predicates) | sofi/conformance.rs::tests::invalid_dominates_and_unavailable_never_becomes_invalid | Behaviour conforms. Affected by the MR-SOFI-0030 fix. |
| MR-SOFI-0205 | Partial | dsm · sofi/validation.rs::validate (L681-767) | sofi/validation.rs test suite | Same gap as 0136: SetupValid per leg is not evaluated (Evidence has no setup field) |
| MR-SOFI-0206 | Met | dsm · sofi/validation.rs::validate (no canonicality/liveness read) | as 0157 | — |
| MR-SOFI-0207 | Met | dsm · sofi/validation.rs::Verdict::note/finish (Invalid dominates Unavailable) | sofi/validation.rs::tests::a_provable_invalidity_is_not_masked_by_missing_evidence; an_invalidity_on_a_later_hop_survives_a_gap_on_an_earlier_one | — |
| MR-SOFI-0208 | Met | dsm · sofi/conformance.rs::Items::fold | sofi/conformance.rs::tests::invalid_dominates_unavailable_in_item_order | — |
| MR-SOFI-0209 | Met | dsm · sofi/conformance.rs::successor_position | sofi/conformance.rs::tests::item_1_the_referenced_p_is_available_verifies_and_q_is_its_successor | — |
| MR-SOFI-0210 | Met | dsm · sofi/conformance.rs::key_is_the_precommitted_one | sofi/conformance.rs::tests::item_2_f_is_signed_under_the_key_p_committed | — |
| MR-SOFI-0211 | Met | dsm · sofi/conformance.rs::policy_set_is_canonical | sofi/conformance.rs::tests::item_3_the_policy_fulfillment_set_is_the_canonical_set_of_p | — |
| MR-SOFI-0212 | Met | dsm · sofi/conformance.rs::attempts_cover_legs | sofi/conformance.rs::tests::item_4_the_attempts_cover_exactly_the_legs_of_p_with_no_holes | — |
| MR-SOFI-0213 | Met | dsm · sofi/conformance.rs (item 5, prior-attempt resolution, L419-433) | sofi/conformance.rs::tests::item_5_an_earlier_attempt_must_have_a_permanent_storage_resolution | — |
| MR-SOFI-0214 | Met | dsm · sofi/conformance.rs (item 6, L438-475) | sofi/conformance.rs::tests::item_6_setup_registered_holds_for_every_leg | — |
| MR-SOFI-0215 | Met | dsm · sofi/conformance.rs (items 7/8, L477-549) | sofi/conformance.rs::tests::item_7_identities_and_bounds_hold; item_8_the_preimage_and_closure_are_available_and_verify | — |
| MR-SOFI-0216 | Met | dsm · sofi/conformance.rs (no Registration param in evidence/predicate) | sofi/conformance.rs::tests::invalid_dominates_unavailable_in_item_order (no registration input at all) | — |
| MR-SOFI-0217 | Met | dsm_sdk · sdk/sofi_register.rs (install refuses unless Valid, L257-270) | dsm_sdk sofi_register.rs test module | Not reachable from any production entry (see summary) |
| MR-SOFI-0218 | Met | dsm · sofi/registration.rs::fulfillment_registered; sofi/publication.rs (any caller relays) | sofi/registration.rs::tests | — |
| MR-SOFI-0219 | Met | dsm · sofi/exercise.rs::attempt_resolution (derived each time from raw reads, no stored outcome) | sofi/exercise.rs::tests::a_successor_key_resolves_to_the_e_of_the_exercise_that_names_it_or_stays_open | — |
| MR-SOFI-0220 | Met | dsm_storage_node (no SoFi awareness; occupancy carries no authority) | dsm_storage_node/tests/cells_keep_everything.rs::a_second_value_at_a_key_is_kept_after_the_first_never_refused | — |
| MR-SOFI-0221 | Met | dsm · sofi/resolution.rs · `consumed_route`, `resolve_position` | `a_route_with_one_leg_still_open_is_not_consumed` | — |
| MR-SOFI-0222 | Partial | dsm · sofi/resolution.rs (no lock field/param anywhere in `RouteFacts`/`LegFacts`) | no test found | No lock field or parameter in `RouteFacts`/`LegFacts`. No test asserts the absence. |
| MR-SOFI-0223 | Met | dsm · sofi/resolution.rs · `trader_parent_compatible`/`trader_parent_impossible` | `a_conditional_parent_that_selected_this_root_processes_normally`, `a_final_cell_whose_fulfillment_lost_its_position_is_skipped` | — |
| MR-SOFI-0224 | Met | dsm · sofi/resolution.rs · `resolve_position` rungs 4/7 | `no_route_becomes_void_while_its_conformance_is_unknown` | — |
| MR-SOFI-0225 | Partial | dsm · sofi/resolution.rs (design: `registered: bool` fact only, no verdict) | no test found | — |
| MR-SOFI-0226 | Met | dsm · sofi/resolution.rs · `consumed_route` (conjoins `registered` and per-leg `final_on`) | `an_unregistered_fulfillment_is_pending_even_with_every_leg_final` | — |
| MR-SOFI-0227 | Met | dsm · sofi/lineage.rs · `descendant_fence`, `PredecessorClaim` | `a_terminal_resolution_never_becomes_an_admitted_position` | — |
| MR-SOFI-0228 | Met | dsm · sofi/resolution.rs · `storage_resolved` used only at rung 7 | `void_requires_storage_resolution` | — |
| MR-SOFI-0229 | Met | dsm · sofi/lineage.rs · `descendant_fence`; ci/admitted_predecessor_readers_fenced.sh | gate script (verified: wired at production_safety_checks.sh:67, checks FENCED_READERS cross `descendant_fence`) | — |
| MR-SOFI-0230 | Met | dsm · sofi/arith.rs · `resolve` | `leader_held_settles_the_race_before_finality` | Pre-S4 model; see 0328 |
| MR-SOFI-0231 | Met | dsm · sofi/resolution.rs · `walk`, `classify_attempt` | `the_walk_is_chunking_equivalent` | — |
| MR-SOFI-0232 | Met | dsm · sofi/resolution.rs · `walk`, `classify_attempt` | `the_walk_is_chunking_equivalent` | — |
| MR-SOFI-0233 | Met | dsm · sofi/resolution.rs · `consumed_route` | `a_route_with_one_leg_still_open_is_not_consumed`; dsm_sdk sofi_resolve.rs uses it | — |
| MR-SOFI-0234 | Met | dsm · sofi/resolution.rs · `trader_parent_compatible`/`trader_parent_impossible` | `the_trader_parent_arm_is_monotone` | — |
| MR-SOFI-0235 | Met | dsm · sofi/resolution.rs · `trader_parent_compatible`/`trader_parent_impossible` | `the_trader_parent_arm_is_monotone` | — |
| MR-SOFI-0236 | Met | dsm · sofi/resolution.rs · `classify_attempt`/`consumed_route` (one E per route) | `legs_final_on_different_commitments_are_not_one_route` | — |
| MR-SOFI-0237 | Met | dsm · sofi/resolution.rs · `route_impossible`, rung 7 | `a_stranded_final_cell_of_an_impossible_route_is_skipped` | — |
| MR-SOFI-0238 | Violated | dsm · sofi/resolution.rs · `route_impossible` (arms i–v never read `RouteFacts.conformance`) | none (bug, not absence) | Confirmed by direct read: `route_impossible` checks `validation`/`parent`/`trader_parent`/`position_lost` only; a conformance‑Invalid F whose final cell sits on the walked key is never skippable — `classify_attempt` returns `Unresolved` forever, stranding the DLV attempt chain. |
| MR-SOFI-0239 | Met | dsm · sofi/resolution.rs · `route_impossible` | `the_orphan_and_consumed_elsewhere_arms_need_no_evidence` | — |
| MR-SOFI-0240 | Met | dsm · sofi/resolution.rs · `route_impossible` | `the_orphan_and_consumed_elsewhere_arms_need_no_evidence` | — |
| MR-SOFI-0241 | Met | dsm · sofi/resolution.rs · `route_impossible`/`classify_attempt` | `the_orphan_and_consumed_elsewhere_arms_need_no_evidence` | — |
| MR-SOFI-0242 | Met | dsm · sofi/resolution.rs · `classify_attempt` | `a_final_leg_of_an_incomplete_route_is_not_consumed` | — |
| MR-SOFI-0243 | Met | dsm · sofi/resolution.rs · `walk` | `the_walk_is_chunking_equivalent` | — |
| MR-SOFI-0244 | Met | dsm · sofi/resolution.rs · `walk` | `the_walk_is_chunking_equivalent` | — |
| MR-SOFI-0245 | Met | dsm · sofi/conformance.rs · `successor_position`; sofi/derive.rs | verified directly (`successor_position` checks `q=p+1`) | — |
| MR-SOFI-0246 | Met | dsm · sofi/resolution.rs · `parent_status` | `a_generation_the_chain_has_not_reached_waits_and_is_never_orphaned` | — |
| MR-SOFI-0247 | Met | dsm · sofi/resolution.rs · `resolve_position` (first-matching-rung ladder) | `a_terminal_resolution_is_never_reached_from_another_terminal_one` | — |
| MR-SOFI-0248 | Partial | dsm · sofi/resolution.rs · `resolve_position` (rungs 0–8, no rung 3a) | ladder-permanence test exists but no rung-3a test (doesn't exist) | Ladder lacks the S5 drop-claim rung |
| MR-SOFI-0249 | Met | dsm · sofi/resolution.rs · `resolve_position` (registration checked at rung 0 before conformance at rung 3) | `an_unregistered_fulfillment_is_pending_even_with_every_leg_final` | — |
| MR-SOFI-0250 | Met | dsm · sofi/resolution.rs · `Resolution`, `effect_of` | `only_realized_installs_the_realize_root_and_void_installs_the_previous_one` | — |
| MR-SOFI-0251 | Met | dsm · sofi/lineage.rs · `advance_resolved` (`ResolutionClaimMismatch`) | `advance_is_refused_on_each_missing_conjunct` | — |
| MR-SOFI-0252 | Partial | dsm · sofi/resolution.rs (stateless verdict) | n/a | Challenge/drop-claim (storage §9.1) half absent — matches 0248/0329 |
| MR-SOFI-0253 | Partial | dsm_sdk · sdk/sofi_sdk.rs / sofi_advance.rs (recompute-from-storage design) | no restart/crash test found | — |
| MR-SOFI-0254 | Met | dsm_sdk · sdk/sofi_sdk.rs · `draft` (stops on non‑`Ok` from `validate`) | `unavailable_stops_the_producer_and_nothing_is_produced` | Prohibition — library test suffices despite dark module |
| MR-SOFI-0255 | Missing | — (no `dsm_sdk/src/handlers/sofi_routes.rs`, no `/api/v2/sofi` in proto) | — | Confirmed: no SoFi verb anywhere in handlers/ or dsm_app.proto |
| MR-SOFI-0256 | Missing | — (no `findRoute`/path-search route anywhere) | — | — |
| MR-SOFI-0257 | Partial | dsm_sdk · sdk/sofi_sdk.rs · `build_vault_create`; dsm · sofi/lineage.rs · `genesis_root`, `vault_leaves_at_genesis` | `a_vault_creation_signs_the_operations_own_bytes`; `the_genesis_root_holds_only_the_state_leaf` | The vault-create producer is tested but has no production entry (§3 G1). |
| MR-SOFI-0258 | Partial | dsm_sdk · sdk/sofi_sdk.rs · `build_setup` | `a_setup_signs_its_object_and_not_the_operation` | Producer tested, no route |
| MR-SOFI-0259 | Partial | dsm_sdk · sdk/sofi_chain.rs · `ChainWalker::chain`/`chain_to_depth` | no test of the walk itself; `sofi_chain.rs` tests (e.g. `a_different_root_at_a_generation_the_chain_reached_is_orphaned`) cover the underlying `VaultChain` facts | No test asserts the walk invariant, and `ChainWalker` has no production caller. |
| MR-SOFI-0260 | Met | dsm_sdk · sdk/sofi_sdk.rs · `draft` | `a_producer_refuses_a_route_that_does_not_chain` | Prohibition |
| MR-SOFI-0261 | Partial | dsm_sdk · sdk/sofi_sdk.rs (`build_fulfillment` publishes but no durability wait) | none found | No check of storage durability before exercise |
| MR-SOFI-0262 | Partial | dsm_sdk · sdk/sofi_sdk.rs · `build_fulfillment` | `an_exercise_is_signed_twice_and_p_travels_with_its_signature`, `a_two_hop_route_that_chains_builds` | The obligation describes an actual exercise; the producer is tested but has no production caller. |
| MR-SOFI-0263 | Met | dsm · sofi/resolution.rs · `classify_attempt`, `route_impossible` | `a_route_with_one_leg_still_open_is_not_consumed`, `a_stranded_final_cell_of_an_impossible_route_is_skipped` | Pure verifier-math, no reachability requirement |
| MR-SOFI-0264 | Met | dsm · sofi/resolution.rs · `classify_attempt`, `route_impossible` | `a_route_with_one_leg_still_open_is_not_consumed`, `a_stranded_final_cell_of_an_impossible_route_is_skipped` | Pure verifier-math, no reachability requirement |
| MR-SOFI-0265 | Partial | dsm_sdk · sdk/sofi_sdk.rs · `draft_close`; dsm · sofi/validation.rs · `validate_close` | `a_close_is_the_same_variant_and_only_the_origin_owner` | No route |
| MR-SOFI-0266 | Partial | dsm_sdk · sdk/sofi_relay.rs · `relay_fulfillment`, `carry_pair` | `a_relayer_completes_the_cells_and_the_owner_later_resolves_from_its_admission` (sofi_advance.rs) | Verified sofi_relay.rs itself has zero `#[test]`s; tests live in sofi_advance.rs and call it. No production caller. |
| MR-SOFI-0267 | Partial | dsm · sofi/smt/mod.rs / fold.rs · `verify_batch`/`fold` | none for "staged frontier validation" specifically | Confirmed: the persistent staged-frontier node store was deleted outright (module doc says so); the replacement (`advance_resolved` + evidence store) doesn't implement "retain only nodes reachable from validated roots" as stated |
| MR-SOFI-0268 | Met | ci/sofi_reachability.py (Gate G1) | gate script, wired at production_safety_checks.sh:50 | Proves Core-layer (dsm/src/sofi) reachability only, not app reachability — see 0255 |
| MR-SOFI-0269 | Met | dsm · sofi/conformance.rs · `ConformanceEvidence` (`Option`/`BTreeMap`, no defaults outside `cfg(test)`) | `item_1_the_referenced_p_is_available_verifies_and_q_is_its_successor` | — |
| MR-SOFI-0270 | Met | dsm · sofi/conformance.rs · `fulfillment_conformance` (8 items, `Items::fold`) | `invalid_dominates_unavailable_in_item_order` | — |
| MR-SOFI-0271 | Met | dsm · sofi/lineage.rs · `advance_resolved` (E recomputed, `C_q` derived not read) | `advance_is_refused_on_each_missing_conjunct` | — |
| MR-SOFI-0272 | Met | dsm_sdk · sdk/sofi_sdk.rs · `draft` | `unavailable_stops_the_producer_and_nothing_is_produced` | Behaviour conforms. Affected by the MR-SOFI-0030 fix. |
| MR-SOFI-0273 | Met | ci/sofi_reachability.py:145-179 | gate script | — |
| MR-SOFI-0274 | Met | dsm · sofi/conformance.rs:150, validation.rs:235 (`#[cfg_attr(test, derive(Default))]`); ci/sofi_no_default_evidence.sh | gate script, wired at production_safety_checks.sh:73 | Verified both `Evidence` and `ConformanceEvidence` derive `Default` only under `cfg(test)` |
| MR-SOFI-0275 | Partial | dsm · sofi/conformance.rs (`item_1`..`item_8` tests); sofi/validation.rs (per-check "X is invalid" tests + `missing_evidence_is_unavailable_never_invalid`) | conformance.rs has strong paired missing/corrupt coverage per item; validation.rs has broad but not exhaustively paired per-item missing+corrupt coverage | — |
| MR-SOFI-0276 | Partial | dsm · sofi/lineage.rs · `advance_resolved`/`genesis_root` | no single consolidated G4 test found (closest: `a_realized_position_installs_the_realize_root`) | — |
| MR-SOFI-0277 | Met | dsm_sdk · sdk/sofi_sdk.rs · `draft` | `unavailable_stops_the_producer_and_nothing_is_produced` (loops over every policy + genesis withheld) | — |
| MR-SOFI-0278 | Met | dsm · types/device_state.rs · `advance` (verify_operation call at L1198-1205 for `SofiSetup`/`SofiVaultCreate`/`SofiFulfill`); core/state_machine/mod.rs · `prepare_advance_relationship` | `a_sofi_setup_advances_only_with_a_signature_over_its_own_digest` | Verified directly |
| MR-SOFI-0279 | Met | dsm · types/device_state.rs · `advance` (verify_operation call at L1198-1205 for `SofiSetup`/`SofiVaultCreate`/`SofiFulfill`); core/state_machine/mod.rs · `prepare_advance_relationship` | `a_sofi_setup_advances_only_with_a_signature_over_its_own_digest` | Verified directly |
| MR-SOFI-0280 | Met | dsm · types/device_state.rs · `derive_transition_entropy` (L954-980) | equality test at device_state.rs:3724 | Verified: exact `H(DSM/state-entropy; e_n‖op‖h_n)` formula |
| MR-SOFI-0281 | Met | dsm · core/state_machine/mod.rs · `prepare_advance_relationship` (sole caller of `DeviceState::advance`) | verified by doc comment + code | — |
| MR-SOFI-0282 | Met | dsm · types/device_state.rs:959-961 (`derive_transition_entropy` takes no entropy param) | device_state.rs:3724 | — |
| MR-SOFI-0283 | Partial | dsm · types/device_state.rs:977 (`operation.to_bytes()` hashed) | no test found | — |
| MR-SOFI-0284 | Partial | dsm · types/device_state.rs (entropy-equality test exists) | device_state.rs:3724 test is generic, not a consolidated per-SoFi-op determinism/gate test | — |
| MR-SOFI-0285 | Not code | — | — | Process rule |
| MR-SOFI-0286 | Met | ci/storage_is_dumb.sh | gate script, wired at production_safety_checks.sh:70 | Verified: bans `dsm::sofi`, `TraderPrecommit`, `RouteValidation`, `ConsumedRoute`, etc. and any case-insensitive "sofi" mention over `dsm_storage_node/src` |
| MR-SOFI-0287 | Met | dsm_storage_node · lib.rs · `storage_contract_router` (cells, immutable and ByteCommit routes carry no auth layer) | `immutable_store_round_trip::a_put_with_no_authorization_is_taken_on_the_served_assembly`; `cells_keep_everything` (served assembly, no authorization header) | A signature or writer check on these routes would refuse the unauthenticated puts these tests make. |
| MR-SOFI-0288 | Met | dsm · types/device_state.rs · `advance`; sofi/signature.rs · `verify_operation` | `a_sofi_setup_advances_only_with_a_signature_over_its_own_digest` | — |
| MR-SOFI-0289 | Met | dsm_storage_node/tests/immutable_store_round_trip.rs | `bytes_put_into_the_immutable_store_come_back_byte_identical` | Verified directly |
| MR-SOFI-0290 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0291 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0292 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0293 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0294 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0295 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0296 | Not code | lean4/, tla/ | — | Formal-model artifacts, per definition |
| MR-SOFI-0297 | Not code | — | — | Dependency-boundary |
| MR-SOFI-0298 | Missing | dsm · common/domain_tags/dsm/misc/sofi.rs:165 (`TAG_DSM_SOFI_MEMBERSHIP_HANDOVER`, "Reserved... Not ruled") | — | Verified: tag allocated, zero derivations use it anywhere |
| MR-SOFI-0299 | Partial | dsm · types/policy_types.rs (`PolicyAnchor`); ccb/state.rs:221-263 | no test found | Plausible from the content-addressed `PolicyAnchor` design; not verified line by line and no test named. |
| MR-SOFI-0300 | Partial | dsm_sdk · handlers/token_routes.rs (`token.create` anchors and locks out issuer); dsm · core/token/policy/mod.rs:246 (`update_token_policy`, dead — zero callers anywhere in repo, verified by grep) | e2e_token_create_lifecycle.rs (creation path); no test needed for dead code | — |
| MR-SOFI-0301 | Partial | dsm · ccb/state.rs (MarketPolicy names token policy commits, no own token policy) | no test found | Not independently re-verified in depth |
| MR-SOFI-0302 | Met | dsm_sdk · handlers/token_routes.rs · `build_policy_v3_bytes` | `token_create_anchor_integrity.rs` (existence) | Verified: sole packer, all fields big-endian |
| MR-SOFI-0303 | Met | dsm_sdk · handlers/token_routes.rs · `parse_token_policy`/`build_policy_v3_bytes` (n≤16 `MAX_POLICY_SIGNERS`, ticker 2-8, decimals ≤18) | inline checks verified directly at L130-271 | — |
| MR-SOFI-0304 | Partial | dsm · types/policy_types.rs (`PolicyAnchor`, content hash) | no test found | — |
| MR-SOFI-0305 | Met | dsm_sdk · handlers/token_routes.rs (ticker only gates registry display/adoption UX, not identity — `policy_commit` is identity) | `token_create_reconciliation.rs` | — |
| MR-SOFI-0306 | Violated | dsm_sdk · handlers/token_routes.rs (`POLICY_FLAG_UNLIMITED_SUPPLY`; `token.create` handler L1337-1342 REFUSES capped creation with "CAPPED_TOKEN_ISSUANCE_UNSUPPORTED_IN_BETA"); dsm · economic/issuance.rs · `check_issuance_permitted` (also refuses any non-unlimited policy: `FiniteSupplyCap`) | `token_mint_burn_routes.rs::a_capped_token_is_refused_at_creation_and_leaves_nothing_behind` | **Strengthened**: not merely "supported" — production code makes unlimited supply the ONLY creatable class and independently refuses finite caps at issuance too. Direct contradiction of "neither class has an unlimited option." |
| MR-SOFI-0307 | Violated | dsm_sdk · handlers/token_routes.rs `token.create`/`handle_token_mint`; dsm · economic/issuance.rs · `check_issuance_permitted` | `token_mint_burn_routes.rs`, `token_authority_enforcement.rs::token_authority_does_not_gate_mint` | This is not merely an absent check. Creation forces `initial_alloc=0` ("supply at creation is refused") and supply is created later, repeatedly, via `token.mint` under discretionary k-of-n signer authorization — the literal opposite of "genesis supply equals unreleased+balances+burned... no minting after genesis." Reclassified from Missing to Violated. |
| MR-SOFI-0308 | Missing | dsm · economic/issuance.rs (module doc explicitly: "DOES NOT PROVE... redeemable for, or collateralized by... no backing condition in the token-policy vocabulary") | — | Confirmed by direct read: no backing/lock/reserve concept anywhere |
| MR-SOFI-0309 | Missing | dsm · economic/issuance.rs (module doc explicitly: "DOES NOT PROVE... redeemable for, or collateralized by... no backing condition in the token-policy vocabulary") | — | Confirmed by direct read: no backing/lock/reserve concept anywhere |
| MR-SOFI-0310 | Met | dsm · economic/issuance.rs · `check_issuance_permitted` (threshold/signer-set check); economic/provenance.rs (signature counting) | `economic_authorized_issuance.rs::two_distinct_policy_signers_fund_the_exact_issuance`, `a_single_signature_does_not_meet_the_threshold`, `an_authority_its_own_signer_set_cannot_satisfy_refuses_the_issuance` | Locus is issuance.rs/provenance.rs, not token_routes.rs (which only clamps/passes the threshold through) |
| MR-SOFI-0311 | Partial | dsm · economic/issuance.rs · `check_market_leg_permitted` | none — confirmed by grep this function has **zero callers anywhere in the repo** (only its own definition) | No transfer, vault-creation or SoFi-leg path calls it. |
| MR-SOFI-0312 | Met | dsm · economic/issuance.rs · `check_issuance_permitted` (allowlist checked against `recipient_devid` only, on mint) | `economic_authorized_issuance.rs::a_device_outside_the_committed_allowlist_is_refused` | — |
| MR-SOFI-0313 | Partial | dsm_sdk · handlers/token_routes.rs · `parse_token_policy` (fail-closed on every field) | inline parse checks verified | No explicit supply-class field (only the unlimited flag), no separate native/backed sub-shapes |
| MR-SOFI-0314 | Partial | dsm_sdk · handlers/token_routes.rs (genesis supply nominally fixed in policy, but capped creation refused — see 0306) | `token_mint_burn_routes.rs::a_capped_token_is_refused_at_creation_and_leaves_nothing_behind` | Tied to 0306 |
| MR-SOFI-0315 | Partial | dsm · core/token/policy/mod.rs:246 · `update_token_policy` (dead, no callers — confirmed by grep) | none needed (uncalled) | — |
| MR-SOFI-0316 | Partial | dsm_sdk · handlers/token_routes.rs · `handle_token_mint` (0x0029-gated, but discretionary signer-triggered, not a policy-committed release formula "verifiable by anyone by recomputing") | `economic_authorized_issuance.rs` | No release-rule vocabulary exists — matches 0307 finding |
| MR-SOFI-0317 | Met | dsm · types/operations.rs (`Burn` destructive; no path returns burned units to unreleased) | `burn_requires_an_admitted_economic_lineage` (token_mint_burn_routes.rs) | — |
| MR-SOFI-0318 | Met | dsm · economic/issuance.rs · `parse_issuance_policy` (reads exact committed bytes, no default/standard fallback) | `economic_authorized_issuance.rs::a_policy_commit_the_authorization_does_not_name_is_refused` | — |
| MR-SOFI-0319 | Missing | — | — | No backing/lock-consumption concept — same absence as 0308 |
| MR-SOFI-0320 | Missing | — | — | No backing/lock-consumption concept — same absence as 0308 |
| MR-SOFI-0321 | Missing | — | — | No redemption transition anywhere |
| MR-SOFI-0322 | Partial | dsm_sdk · handlers/token_routes.rs, dsm · economic/issuance.rs | `token_mint_burn_routes.rs` | Native supply is not fixed at genesis in practice (0307); no backed class exists (0308) |
| MR-SOFI-0323 | Missing | — | — | No conversion-rule mechanism anywhere |
| MR-SOFI-0324 | Missing | — | — | No conversion-rule mechanism anywhere |
| MR-SOFI-0325 | Missing | — | — | No conversion-rule mechanism anywhere |
| MR-SOFI-0326 | Partial | dsm · economic/issuance.rs · `check_issuance_permitted` (`policy.mint_burn_enabled` gates BOTH `"mint"` and `"burn"` identically) | `economic_authorized_issuance.rs::a_policy_with_mint_burn_disabled_refuses_the_issuance` (covers mint path; same flag used for burn) | Verified: one flag governs both, spec wants burns-only |
| MR-SOFI-0327 | Partial | dsm · economic/issuance.rs, dsm_sdk · handlers/token_routes.rs | economic_authorized_issuance.rs has good per-rule named tests (`a_finite_supply_cap_refuses_the_issuance`, `a_device_outside_the_committed_allowlist_is_refused`, etc.) — but not exhaustively confirmed for every rule | Reasonable coverage exists; not fully enumerated |
| MR-SOFI-0328 | Missing | dsm · sofi/arith.rs · `resolve` (implements old leader/quorum model only, no route-chain / two-further-valid-links semantics) | leader_held_settles_the_race_before_finality (tests the OLD model) | S4 amendment (2026-09-22) mechanism not built |
| MR-SOFI-0329 | Missing | dsm · sofi/resolution.rs · `resolve_position` (no rung 3a / drop-claim arm) | — | S5 amendment (2026-09-22) mechanism not built |

### 8.3 dBTC native specification

MR-DBTC-0001 to MR-DBTC-0135: **Deferred** (dBTC is out of this round). So are MR-DSM-0198 and MR-DSM-0221–0237 (§6.1), and the dBTC code findings: `vault/limbo_vault.rs::verify_bitcoin_htlc` degrades to an amount-only check when the script is absent, and the confirmation depth counts `header_chain.len() + 1`.

### 8.4 Storage node specification

| MR-ID | Status | Code (crate · file · function) | Test | Gap / note |
|---|---|---|---|---|
| MR-STOR-0001 | Not code | — | — | Spec hierarchy |
| MR-STOR-0002 | Not code | — | — | Process rule |
| MR-STOR-0003 | Not code | — | — | Reading rule |
| MR-STOR-0004 | Not code | — | — | Normative words |
| MR-STOR-0005 | Partial | dsm_storage_node · crate-wide (no key/sign symbols) | no test found | True today; no gate or test fails if a key or signing path is added |
| MR-STOR-0006 | Violated | dsm_storage_node · api/identity/authenticate.rs `authenticate_vaultpost_smart_policy_if_present` (from api/objects/store.rs `put_object`); api/transport/b0x.rs `is_cert_resync_recovery` | authenticate.rs `authenticate_vaultpost_crypto_condition_empty_public_params_rejected`; b0x.rs `exempts_resync_methods_only_and_bounded` (these tests assert the forbidden behaviour) | Node evaluates payload structure and branches on decoded `Invoke.method` |
| MR-STOR-0007 | Violated | as 0006 | as 0006 | — |
| MR-STOR-0008 | Partial | dsm_storage_node · crate-wide (logical ticks, BIGSERIAL) | no test found | No clock reads; no enforcing test |
| MR-STOR-0009 | Met | dsm_storage_node · replication.rs `process_gossip`; api/transport/gossip.rs `gossip_receive` | replication.rs `process_gossip_adds_new_nodes`, `process_gossip_suspects_stale_nodes`, `process_gossip_marks_suspected_as_dead` | No election/vote |
| MR-STOR-0010 | Violated | as 0006 | as 0006 | — |
| MR-STOR-0011 | Partial | dsm_storage_node · crate-wide | no test found | True today; not regression-proof |
| MR-STOR-0012 | Met | dsm · sofi/storage.rs `counts`, `stored`; sofi/arith.rs `resolve_objects` | storage.rs `wrong_bytes_never_count`; arith.rs `the_adapter_derives_final_from_the_recognized_view` | — |
| MR-STOR-0013 | Met | dsm · sofi/arith.rs `resolve`, `resolve_objects` | arith.rs `an_unreachable_leader_resolves_nothing_and_no_member_stands_in`; storage.rs `silence_never_counts` | — |
| MR-STOR-0014 | Violated | dsm_storage_node · db/pg.rs `upsert_object`, `upsert_object_with_capacity_check` (ON CONFLICT DO UPDATE), `delete_slot_object` (DELETE); routes `/api/v2/object/put`, `/api/v2/object/delete_proto` (main.rs) | none | Live overwrite and delete of held bytes |
| MR-STOR-0015 | Missing | no code found | — | No stale-snapshot / loss detection |
| MR-STOR-0016 | Partial | dsm_storage_node · api/objects/immutable.rs `get_immutable`; dsm · sofi/storage.rs `stored` | no test found | Mismatch branch untested |
| MR-STOR-0017 | Not code | — | — | Fault-boundary assumption |
| MR-STOR-0018 | Met | dsm · sofi/arith.rs `resolve` | `an_unreachable_leader_resolves_nothing_and_no_member_stands_in` | — |
| MR-STOR-0019 | Missing | no code found | — | "seat" is comment vocabulary only |
| MR-STOR-0020 | Partial | dsm · sofi/storage.rs `stored`; sofi/arith.rs `resolve` | arith/storage tests | LeaderHeld/Final implemented with the superseded count rule |
| MR-STOR-0021 | Met | dsm · sofi/arith.rs `ObjectResolution::{Open,Unavailable}` | `the_adapter_tells_open_from_unavailable_at_the_leader` | — |
| MR-STOR-0022 | Met | dsm · storage_object.rs `immutable_addr`; dsm_storage_node · api/objects/immutable.rs `put_immutable` | storage_object.rs `the_address_matches_the_spec_construction` | — |
| MR-STOR-0023 | Partial | dsm_storage_node · api/objects/immutable.rs `put_immutable` (x-expected-addr) | no test found | No test sends a mismatching address |
| MR-STOR-0024 | Violated | dsm_storage_node · db/pg.rs `upsert_object` (legacy store, mounted beside the immutable store) | none | The immutable store has no update path; the legacy store in the same router overwrites |
| MR-STOR-0025 | Partial | dsm_storage_node · db/pg.rs `insert_immutable_object_if_absent`; immutable.rs `put_immutable` | tests/immutable_store_round_trip.rs `re_putting_identical_bytes_acks_and_the_read_is_unchanged` | Tested on Postgres since the SQLite backend was deleted (2026-09-24), the conflict branch included (`db::store_properties::immutable_put_is_write_once_on_the_tuple`, `a_conflicting_put_leaves_the_first_write_untouched`). |
| MR-STOR-0026 | Partial | dsm_storage_node · api/objects/immutable.rs `get_immutable` | no test found | Recompute-and-refuse branch untested |
| MR-STOR-0027 | Met | dsm · sofi/storage.rs `stored`; sofi/wire/mod.rs `STORAGE_FINALITY_COUNT` | `two_members_is_not_stored`, `stored_returns_exact_bytes` | — |
| MR-STOR-0028 | Met | dsm_storage_node · api/cells.rs `put_cell`/`put_cells` → db `put_cell` | tests/cells_keep_everything.rs `an_identical_value_put_twice_is_held_twice` | — |
| MR-STOR-0029 | Met | dsm_storage_node · api/cells.rs `get_cell` → db `get_cell_entries` | cells_keep_everything.rs `a_key_nothing_was_put_under_reads_as_an_empty_list_with_200` | — |
| MR-STOR-0030 | Violated | dsm_storage_node · api/cells.rs (conforms); api/objects/store.rs · `put_object`, `delete_object_proto`; db/pg.rs · `upsert_object` (`ON CONFLICT DO UPDATE`); auth/mod.rs · `device_auth` on object and b0x writes | cells_keep_everything.rs `a_second_value_at_a_key_is_kept_after_the_first_never_refused`, `only_malformed_requests_are_refused` | Reconciled Met → Violated (ChatGPT CG-09, CG-11). The cell path conforms, but mounted routes on the same node authenticate writers and replace held values. Same cause as MR-STOR-0041 (G4). |
| MR-STOR-0031 | Met | dsm_storage_node · lib.rs `storage_contract_router` (no auth layer) | cells_keep_everything.rs (served assembly, no auth) | — |
| MR-STOR-0032 | Met | dsm_storage_node · api/cells.rs `append_index`/`read_index`; db/pg.rs | cells_keep_everything.rs `an_index_pages_in_append_order_from_the_last_seq` | — |
| MR-STOR-0033 | Partial | dsm_storage_node · api/identity/tips.rs `get_head`/`put_head`/`get_leaf`/`put_leaf` | tips.rs `key_head_is_deterministic` (key derivation only) | Route behaviour untested |
| MR-STOR-0034 | Violated | dsm_storage_node · api/transport/b0x.rs `submit_b0x_envelope` (decodes the envelope), `is_cert_resync_recovery` | b0x.rs `exempts_resync_methods_only_and_bounded` | Node opens spool envelopes and branches on content |
| MR-STOR-0035 | Met | dsm_storage_node · api/identity/{genesis,devtree,recovery_anchor}.rs; api/vault/recovery.rs | devtree.rs in-file tests | Dependency boundary; substrate present |
| MR-STOR-0036 | Met | dsm · core/bilateral_relationship_manager.rs `accept_contact_request`, `handle_contact_establishment_request/_response` | `test_contact_establishment_request_signature_verification`, `test_contact_establishment_response_signature_verification` | — |
| MR-STOR-0037 | Partial | dsm_sdk · handlers/inbox_routes.rs `handle_inbox_query`; dsm_storage_node · api/transport/b0x.rs routing | b0x.rs `a_submitted_envelope_is_read_back_from_its_spool` (Postgres) | The spool round-trip runs; SDK-side inbox routing is not yet exercised against a node (the SDK harness rewrite, §5A). |
| MR-STOR-0038 | Partial | dsm · core/bilateral_relationship_manager.rs; dsm_sdk · storage/client_db/contacts.rs | not traced | Sender-side refusal not traced |
| MR-STOR-0039 | Partial | as 0038 | not traced | Receive-side signature gate not traced |
| MR-STOR-0040 | Partial | — | not traced | Device-side §11 checks not traced |
| MR-STOR-0041 | Violated | dsm_storage_node · api/transport/b0x.rs `router` (`.layer(device_auth)`); auth/mod.rs `device_auth` | auth/mod.rs `auth_format_tests` (parser only) | Node checks the writer |
| MR-STOR-0042 | Met | dsm · route_chain.rs `Route::of`/`Route::leader`; sofi/fisher_yates.rs `first_member` | exercise.rs `an_attempt_cells_leader_is_the_first_member_of_the_seeded_shuffle_over_s`; route_chain.rs `a_route_is_the_fisher_yates_permutation_of_the_committed_set` | Node-side object placement exists in replication.rs (code→spec) |
| MR-STOR-0043 | Met | dsm · sofi/exercise.rs `AttemptCell`; sofi/derive.rs `storage_seed` | exercise.rs `an_attempt_cells_leader_is_bound_to_the_vault_and_the_parent_root` | — |
| MR-STOR-0044 | Met | dsm · route_chain.rs `RoutedCell::new` | route_chain.rs `a_cell_is_routed_only_over_the_committed_set` | — |
| MR-STOR-0045 | Partial | — | not traced | Recognition-before-read not verified across SDK read sites ChatGPT CG-03 (see MR-DSM-0041). |
| MR-STOR-0046 | Partial | dsm · sofi/arith.rs `resolve` | arith.rs tests | Count rule, not route chain |
| MR-STOR-0047 | Partial | as 0046 | as 0046 | — |
| MR-STOR-0048 | Met | dsm · sofi/arith.rs `resolve` | `an_unreachable_leader_resolves_nothing_and_no_member_stands_in` | — |
| MR-STOR-0049 | Met | dsm · route_chain.rs `Route::of`; sofi/fisher_yates.rs `permute` | route_chain.rs `a_route_is_the_fisher_yates_permutation_of_the_committed_set`; `a_cell_is_routed_only_over_the_committed_set` | — |
| MR-STOR-0050 | Missing | no code found | — | No challenge / drop claim |
| MR-STOR-0051 | Missing | no code found | — | — |
| MR-STOR-0052 | Missing | no code found | — | — |
| MR-STOR-0053 | Missing | no code found | — | — |
| MR-STOR-0054 | Missing | no code found | — | — |
| MR-STOR-0055 | Met | dsm_sdk · sdk/storage_set.rs `compute_storage_set_id`, `StorageSet::new` | `set_id_is_order_independent_and_length_prefixed` | Spec amended to match the code (SoFi Amendment S6, storage §10, owner 2026-09-23): the set id covers member id and register-incarnation pairs. |
| MR-STOR-0056 | Met | dsm · economic/register.rs (pinned-set re-derivation); economic/native_reserve.rs `NativeReserveState::genesis` | dsm_sdk storage_set.rs `the_pinned_beta_set_id_is_the_one_every_provisioned_member_logged` | — |
| MR-STOR-0057 | Partial | dsm_sdk · sdk/storage_set.rs `StorageSetCatalog::from_env_config` | `catalog_resolves_only_by_rehash_and_never_falls_back` | One configured set for every party |
| MR-STOR-0058 | Missing | dsm_sdk · sdk/storage_set.rs `from_env_config` (static config, no FY draw) | — | — |
| MR-STOR-0059 | Missing | no code found | — | No opt-out |
| MR-STOR-0060 | Missing | no code found | — | No storage credits |
| MR-STOR-0061 | Missing | no code found | — | No seat type |
| MR-STOR-0062 | Missing | no code found | — | — |
| MR-STOR-0063 | Partial | dsm · route_chain.rs `Route`; sofi/fisher_yates.rs | route_chain.rs route tests | Committed set fixed; seat/occupant half absent |
| MR-STOR-0064 | Missing | no code found | — | — |
| MR-STOR-0065 | Missing | no code found | — | — |
| MR-STOR-0066 | Missing | no code found | — | — |
| MR-STOR-0067 | Missing | no code found | — | — |
| MR-STOR-0068 | Missing | no code found | — | — |
| MR-STOR-0069 | Missing | no code found | — | — |
| MR-STOR-0070 | Missing | no code found | — | — |
| MR-STOR-0071 | Missing | no code found | — | — |
| MR-STOR-0072 | Missing | no code found | — | — |
| MR-STOR-0073 | Missing | — | no test found | Confirmed; no retirement-record concept anywhere. |
| MR-STOR-0074 | Missing | — | no test found | Confirmed. |
| MR-STOR-0075 | Not code | — | — | Theorem. |
| MR-STOR-0076 | Missing | — | no test found | Confirmed (`seat-bind` tag not present anywhere in repo). |
| MR-STOR-0077 | Missing | — | no test found | Confirmed (`rebind` tag not present; only unrelated `rebind()` test helper in `sofi/validation.rs`). |
| MR-STOR-0078 | Missing | — | no test found | Confirmed. |
| MR-STOR-0079 | Missing | — | no test found | Confirmed; no `handover` code anywhere. |
| MR-STOR-0080 | Missing | dsm_storage_node · db/pg.rs · `close_cycle` (per-member_id chain only) | no test found | ByteCommit chaining exists, but cross-operator (handover) continuation does not. |
| MR-STOR-0081 | Missing | dsm · storage_cell.rs · `is_drain_proof` (no production caller) | dsm::storage_cell::tests::`a_drain_proof_is_two_linked_empty_bytecommits` (tests the predicate only, not this requirement) | Predicate is closer to 0097 (stake) than to this "serves until handover" liveness rule; no handover code exists at all. |
| MR-STOR-0082 | Partial | dsm_storage_node · db/pg.rs · `require_durable_commit_posture`, `begin_durable_write` | db::pg::durable_posture_tests::`a_fully_durable_server_is_accepted_in_any_letter_case`, `a_weaker_posture_is_refused_and_the_refusal_names_the_setting` | Requirement rewritten 2026-09-23 (storage §12.5; G14). Each seat's durable write before answering is implemented and tested; counting a write only at three chained links is not built (G2). |
| MR-STOR-0083 | Missing | — | no test found | Confirmed. |
| MR-STOR-0084 | Missing | — | no test found | Confirmed; no loss/pre-loss resolution code. |
| MR-STOR-0085 | Missing | — | no test found | Same as 0084. |
| MR-STOR-0086 | Not code | — | — | Theorem. |
| MR-STOR-0087 | Violated | dsm_storage_node · db/pg.rs (`upsert_registry_node`/`deactivate_registry_node`); api/registry/scaling.rs · `trigger_registry_update` | no test found | Confirmed mutable SQL table, admin-token-gated (admin.rs:227 `admin_surface`), not an immutable object/pure function. |
| MR-STOR-0088 | Violated | dsm_storage_node · api/registry/scaling.rs · `trigger_registry_update` (admin_routes, admin.rs:227) | no test found | Confirmed: node ranks/adds/prunes directly; no keyed-cell candidate mechanism. |
| MR-STOR-0089 | Partial | dsm_storage_node · api/registry/scaling.rs · `submit_up_signal`/`submit_down_signal` (store); `trigger_registry_update` (decides) | no test found | Confirmed: signals stored as evidence, ΔP/decision computed node-side. |
| MR-STOR-0090 | Partial | dsm_storage_node · api/registry/scaling.rs · `trigger_registry_update` (DOM_ORDER salted rank) | scaling::tests::`applicant_ranking_is_deterministic_and_sortable` | Confirmed: salted, deterministic ranking; no commit-reveal, node-side not keyed-cell. |
| MR-STOR-0091 | Met | dsm_storage_node · api/registry/scaling.rs · `GRACE_CYCLES`/`count_down_signals_excluding_grace` | scaling::tests::`constants_match_spec` | Confirmed GRACE_CYCLES=8, cycle-counted. |
| MR-STOR-0092 | Partial | dsm_storage_node · api/registry/scaling.rs · `trigger_registry_update` (utilization prune) | scaling::tests::`pruning_sort_by_utilization_then_node_id` | Sort logic tested; cadence-regularity criterion absent, node-decided. |
| MR-STOR-0093 | Met | dsm_storage_node · db/pg.rs · `close_cycle`; dsm · storage_cell.rs · `ByteCommit` | dsm::storage_cell::tests::`the_bytecommit_digest_matches_the_spec_construction`; bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` | Confirmed. |
| MR-STOR-0094 | Missing | — (no dsm_sdk caller of `record_is_committed`/`CellCommitProof`) | no test found | Confirmed via grep: zero hits in dsm_sdk. |
| MR-STOR-0095 | Missing | dsm_storage_node · api/registry/scaling.rs (signals stored, never checked against ByteCommits) | no test found | Confirmed. |
| MR-STOR-0096 | Met | dsm · storage_cell.rs · `entry_digest`/`running_hash_next`; dsm_storage_node · db/pg.rs · `append_cell_entry` | dsm::storage_cell::tests::`the_running_hash_matches_the_spec_construction`, `any_change_to_earlier_entries_breaks_later_records` | Confirmed. |
| MR-STOR-0097 | Partial | dsm · storage_cell.rs · `ByteCommit::is_drain_proof`; dsm_storage_node · api/registry/scaling.rs · `submit_applicant` (stake_dlv stored opaque) | dsm::storage_cell::tests::`a_drain_proof_is_two_linked_empty_bytecommits` | Predicate exists and is tested in isolation; no stake-unlock caller wires it. |
| MR-STOR-0098 | Not code | — | — | Theorem. |
| MR-STOR-0099 | Partial | dsm_storage_node · api/vault/paidk.rs · `submit_receipt`, `DEFAULT_K`/`DEFAULT_FLAT_RATE` | paidk::tests::`constants_match_spec`; tests/paidk_gating.rs::`t_b_paid_device_accepted`, `t_d_idempotent_already_paid` | `tests/paidk_gating.rs` no longer exists on this branch; no PaidK test runs. |
| MR-STOR-0100 | Violated | dsm_storage_node · api/transport/b0x.rs::`submit_b0x_envelope` (`require_paidk(&app,&_ctx.device_id)`); **also** api/objects/store.rs::`put_object`/`delete_object_proto` (`device_ctx.device_id`) | no test found | Both call sites key the gate on the authenticated caller, never the addressed account (`recipient_spool_key` / `dlv_id`). |
| MR-STOR-0101 | Not code | — | — | Dependency boundary. |
| MR-STOR-0102 | Missing | — | no test found | Confirmed no storage-credit leaf anywhere in `dsm/src`. |
| MR-STOR-0103 | Missing | — | no test found | Confirmed. |
| MR-STOR-0104 | Missing | — | no test found | Confirmed. |
| MR-STOR-0105 | Missing | — | no test found | Confirmed. |
| MR-STOR-0106 | Missing | — | no test found | Vacuous — no credits to count. |
| MR-STOR-0107 | Missing | — | no test found | Confirmed. |
| MR-STOR-0108 | Partial | dsm_sdk · sdk/storage_io.rs · `write_cell_leader_first`/`CellWrite{leader_reached,copies}` | no test found (copy-count only; no 3-link chain assertion) | Payment and admission are decoupled, but "getting through" is an old copy count, not a route-chain check. |
| MR-STOR-0109 | Violated | dsm_storage_node · api/vault/paidk.rs · `require_paidk`; callers api/objects/store.rs::`put_object`/`delete_object_proto`, api/transport/b0x.rs::`submit_b0x_envelope` | tests/paidk_gating.rs::`t_a_unpaid_device_rejected` | Reconciled Met → Violated (ChatGPT CG-10). The gate is keyed on the connected writer, not the addressed account, and reaches paths the exemption covers. Owner decision 2026-09-23: the spend gate is out of beta and is being removed; the permission is then simply unused. |
| MR-STOR-0110 | Violated | same as MR-STOR-0100 | no test found | Same defect, both b0x.rs and store.rs. |
| MR-STOR-0111 | Partial | dsm_storage_node · api/vault/slot.rs · `put_slot`/`get_slot` (no `require_paidk` call) | no test found (slot.rs's create/get test runs on Postgres; it does not assert the exemption) | Slot writes carry no PaidK call. No test asserts the exemption. |
| MR-STOR-0112 | Partial | dsm_storage_node · api/vault/paidk.rs · `require_paidk` (402) | tests/paidk_gating.rs::`t_a_unpaid_device_rejected` | 402 confirmed; no opt-out/cut resolution path exists. |
| MR-STOR-0113 | Missing | — | no test found | Confirmed, vacuous. |
| MR-STOR-0114 | Missing | — | no test found | Vacuous. |
| MR-STOR-0115 | Partial | dsm_sdk · sdk/storage_set.rs (module doc, lines 22-24: "the catalog holds exactly the one configured fleet… immutable for the lifetime of every vault") | no test found | The "one pinned fleet, immutable for the lifetime of every vault" rule is stated and implemented in `dsm_sdk/src/sdk/storage_set.rs`. No test. |
| MR-STOR-0116 | Violated | dsm_storage_node · db/pg.rs::`cleanup_expired_objects_and_spool` (`DELETE FROM objects WHERE iter_expires…`); **also** db/pg.rs::`delete_slot_object` via api/objects/store.rs::`delete_object_proto` | no test found | Two instances: the TTL cleanup (`cleanup_expired_objects_and_spool`), and `delete_object_proto` (`POST /api/v2/object/delete_proto`, device_auth-gated), which issues `DELETE FROM objects WHERE key = $1` on every call. |
| MR-STOR-0117 | Partial | dsm_storage_node · api/objects/immutable.rs::`get_immutable`; api/cells.rs::`get_cell`; api/objects/bytecommit.rs::`proof` (no credit/auth check on any) | no test found | No credit concept exists; reads carry no auth. No test asserts reads stay free. |
| MR-STOR-0118 | Violated | same as 0116 | no test found | Confirmed: pruning driven by load thresholds, not a specified window. |
| MR-STOR-0119 | Violated | same as 0116 | no test found | Confirmed: retention tied to `iter_expires`. |
| MR-STOR-0120 | Partial | dsm_storage_node · api/objects/immutable.rs::`put_immutable` | immutable_store_round_trip::`re_putting_identical_bytes_acks_and_the_read_is_unchanged` | The suite runs on Postgres since the SQLite backend was deleted (2026-09-24). |
| MR-STOR-0121 | Partial | dsm_storage_node · api/cells.rs (no repair endpoint; put/get/index only) | no test found | Confirmed no client-repair path exists (prohibition trivially met); the referenced handover/loss resolution machinery does not exist either. |
| MR-STOR-0122 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0123 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0124 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0125 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0126 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0127 | Not code | — | — | Proof obligations. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0128 | Missing | — | no test found | Confirmed; no Part III succession exists to refine SoFi membership. |
| MR-STOR-0129 | Met | dsm_storage_node · api/cells.rs::`put_cell`/`get_cell`; dsm · storage_cell.rs::`ArrivalRecord` | cells_keep_everything::`a_put_answers_with_the_arrival_record_a_verifier_replays` | Confirmed. |
| MR-STOR-0130 | Partial | dsm_sdk · sdk/storage_io.rs::`write_cell_leader_first`; sdk/storage_node_sdk.rs::`put_cell_leader_first` | no test found for chain-carrying (leader-first order itself is tested, e.g. `faucet_flow_tests::…assert!(write.leader_reached)`) | Leader-first order confirmed live and heavily used (sofi_register/advance/exercise, native_reserve, economic_registers); no chain object is built or carried. |
| MR-STOR-0131 | Missing | — (no `RouteEntryV1`/link type in proto or Rust) | no test found | Confirmed via grep of `proto/dsm_app.proto` and repo-wide search. |
| MR-STOR-0132 | Partial | dsm · sofi/arith.rs::`resolve`/`resolve_objects` (`CellResolution::LeaderHeld`) | dsm::sofi::arith::tests::`a_later_value_at_the_leader_never_becomes_final`, `the_adapter_derives_final_from_the_recognized_view` | This is the pre-2026-09-22 finality rule ("first at leader + held by two others") that storage spec §23.1 item 7 explicitly superseded (Amendment S4/A6); it is still the **live production** computation (called from `sofi_register.rs`, `sofi_advance.rs`, `sofi_exercise.rs`, `native_reserve.rs`, `economic_registers.rs`). It happens to satisfy the narrow "first recognized object at leader" clause of 0132, but is not a chain/link. |
| MR-STOR-0133 | Missing | dsm · sofi/arith.rs::`resolve` (copy count only) | arith::tests::`copies_count_wherever_the_value_sits_in_a_copys_list` (demonstrates the count-only mechanism this requirement replaces, not compliance) | Confirmed no chain-validity, position, or mirror-coverage check anywhere. |
| MR-STOR-0134 | Missing | dsm_sdk · sdk/storage_io.rs::`CellWrite{leader_reached,copies}` | no test found | Confirmed: aggregate counters only, no per-seat empty (`taken`/`no_response`) tracking. |
| MR-STOR-0135 | Met | dsm_storage_node · api/cells.rs::`put_cell`/`get_cell` | cells_keep_everything::`a_second_value_at_a_key_is_kept_after_the_first_never_refused`, `an_identical_value_put_twice_is_held_twice` | Confirmed. |
| MR-STOR-0136 | Partial | dsm_storage_node · api/objects/bytecommit.rs (arrival records verifiable once cycle closes) | bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` | Covers "verifiable once ByteCommit closes"; there is no "link" object to carry forward at all. |
| MR-STOR-0137 | Partial | dsm_sdk · sdk/storage_node_sdk.rs::`put_cell_leader_first`/`put_cells_leader_first` (writes all 5 seats, leader first) | no test found for "any party MAY continue a chain" | Confirmed: all-five-seat write is live; nothing to continue since no chain exists. |
| MR-STOR-0138 | Missing | dsm · sofi/arith.rs::`CellResolution`/`ObjectResolution` (only LeaderHeld/Final, no Preserved) | no test found | Confirmed — third state absent from both enums. |
| MR-STOR-0139 | Missing | — | no test found | Confirmed; no loss-marker/pre-loss code anywhere. |
| MR-STOR-0140 | Met | dsm_storage_node · api/objects/bytecommit.rs::`sync_one`/`fetch_commit` | bytecommit_chain::`a_set_mate_mirrors_by_fetching_from_the_member_itself` | Confirmed. |
| MR-STOR-0141 | Met | dsm_storage_node · api/objects/bytecommit.rs::`fetch_commit` (echo-id check); db/pg.rs::`mirror_put` | bytecommit_chain::`an_impostor_at_a_set_mates_endpoint_is_not_mirrored` | Confirmed. |
| MR-STOR-0142 | Met | dsm_storage_node · db/pg.rs::`mirror_put` (`ON CONFLICT DO NOTHING`) | bytecommit_chain::`a_rewritten_cycle_is_kept_beside_the_first` | Confirmed. |
| MR-STOR-0143 | Not code | — | — | Proof obligation. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0144 | Not code | — | — | Proof obligation. G15: the existing finality tests and formal model prove the superseded copy rule and must be redone for route chains (ChatGPT CG-13). |
| MR-STOR-0145 | Partial | dsm_storage_node · api/transport/b0x.rs; db · `spool_list_from_seq` | — | Added 2026-09-23. Ack, status, expiry and the unpositioned read removed; not yet compiled. |
| MR-STOR-0146 | Missing | — | — | Added 2026-09-23. Payloads are stored in the clear (G16). |
| MR-STOR-0147 | Deferred | — | — | Added 2026-09-23. Continuing storage payment; outside beta. |

### 8.5 Storage §14 lines added after the pin

| MR-ID | Status | Code (crate · file · function) | Test | Gap / note |
|---|---|---|---|---|
| STOR-014/L411 | Met | dsm · storage_cell.rs::`entry_digest` | dsm::storage_cell::tests::`the_running_hash_matches_the_spec_construction` | Confirmed (indirect, via `replay`). |
| STOR-014/L412 | Met | dsm · storage_cell.rs::`running_hash_init`/`running_hash_next` | same as above | Confirmed. |
| STOR-014/L413 | Met | dsm · storage_cell.rs::`ArrivalRecord`; dsm_storage_node · api/cells.rs::`put_cell`/`get_cell` | cells_keep_everything::`a_put_answers_with_the_arrival_record_a_verifier_replays` | Router-level test. |
| STOR-014/L414 | Met | dsm · storage_cell.rs::`leaf_key`/`leaf_value`; dsm_storage_node · db/pg.rs::`cell_leaves_tx` (`DISTINCT ON`) | dsm::storage_cell::tests::`the_leaf_matches_the_spec_construction`; bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` | Confirmed. |
| STOR-014/L415 | Missing | — (no `RouteEntryV1` in `proto/dsm_app.proto` or Rust) | no test found | Confirmed via grep. |
| STOR-014/L419 | Met | dsm · storage_cell.rs::`ByteCommit`, `ByteCommit::from_proto` | dsm::storage_cell::tests::`an_empty_member_id_or_cycle_zero_is_refused` | Confirmed. |
| STOR-014/L420 | Met | dsm · storage_cell.rs::`ByteCommit::digest` | dsm::storage_cell::tests::`the_bytecommit_digest_matches_the_spec_construction` | Confirmed. |
| STOR-014/L421 | Met | dsm_storage_node · db/pg.rs::`close_cycle`, `cell_leaves_tx` | bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` | Confirmed. |
| STOR-014/L422 | Met | dsm_storage_node · db/pg.rs::`close_cycle` (`pending` check) | bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` ("no new entry, no new cycle") | Confirmed. |
| STOR-014/L423 | Partial | dsm_storage_node · db/pg.rs::`cell_commit_proof`; api/objects/bytecommit.rs::`proof` | bytecommit_chain::`cycles_close_over_new_entries_and_commit_their_records` (node-serving side only) | Confirmed no SDK/Core verifier consumer (grep: 0 hits for `record_is_committed`/`CellCommitProof` in `dsm_sdk`). |
| STOR-014/L424 | Met | dsm_storage_node · api/objects/bytecommit.rs::`mirror_sync`/`sync_one`/`fetch_commit`; db/pg.rs::`mirror_put` | bytecommit_chain::`a_set_mate_mirrors_by_fetching_from_the_member_itself`, `an_impostor_at_a_set_mates_endpoint_is_not_mirrored`, `a_rewritten_cycle_is_kept_beside_the_first` | Confirmed. |
