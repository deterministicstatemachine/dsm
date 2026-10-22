# Security audit open rows: fix plan

Status: proposed, 2026-10-22. Nothing here is built. Base: `origin/main` at `c69a3b72` (#1146).
Paths are relative to `dsm_client/deterministic_state_machine/` unless they start with `crates/`, `specs/` or `.github/`.

**Goal:** close every row of the 2026-10-15 and 2026-10-18 security audits (CONFORMANCE_GAPS §6.84, §6.89, §6.90) that the owner approved and that is not done, fix the Coverage regression #1142 left on `main`, and put the design-gated rows to the owner as plain questions.

**Architecture:** one working branch, `fix/security-audit-open-rows`, cut from `origin/main`, with one verified commit per task and one PR at the end. Every fix lands with a test that performs the attack, an in-place mutation that turns that named test red, and its CONFORMANCE_GAPS row and VERIFICATION_MATRIX entry.

**Tech stack:** Rust (`dsm`, `dsm_sdk`, `crates/dsm-app-host`), SQLite client DB, protobuf wire (`proto/`), storage node on Postgres for the end-to-end tests.

**Spec:** `specs/DSM_High_Level_Explainer.md` (A3, A8, A18, A19, §70), `specs/SoFi_Settlement_Specification.md` (§25, §51), `specs/DSM_Storage_Node_Specification.md` (§4, §9). The rows and owner rulings are in `specs/requirements/CONFORMANCE_GAPS.md` §6.84, §6.89 ("Owner rulings on the design questions, 2026-10-18", "Open, next") and §6.90 ("Open").

**Execution:** native, in the main session. The owner's standing rule is that agents are read-only, so the skill's subagent-driven option does not apply.

---

## 1 What was checked, and the result

| Check | How | Result |
|---|---|---|
| The worktree's base | `git fetch`; the worktree was on a pre-rewrite `main` (2026-10-04) | Moved to `origin/main` `c69a3b72` before any check |
| Every test a "Fixed" row cites still exists | 128 test names extracted from §6.84 to §6.90, each `git grep -w` on `origin/main` | 122 present. 6 deleted on purpose: SA-95's and SA-135's tests went with A14's mechanisms (§6.90), SA-92's fork-refusal test went with A14, and SA-07's two 8 MiB budget tests went when SA-67's streaming recognition replaced the budget. §6.86 and the SA-92 entry still cite the deleted names. |
| The fixed tests pass | `main` CI on `c69a3b72` | CI green (Rust board, dsm, dsm_sdk, workspace-rest, Android). **Coverage red on every run since #1142 merged** (it was green at `7e23a388`): `crates/dsm-app-host/tests/real_connection.rs` `a_game_and_a_wallet_connect_over_the_real_relay` times out at "wallet accepts the creature: request 1 is unanswered" after 240 s. In release CI the same test passes in about 65 s. Cause unknown. |
| Each "Open" or "Partial" row is still open | Each row's cited files diffed between its audit commit (`f160d22c` or `7e23a388`) and `origin/main`. Where a file changed, the named function was read | Every one is still open by code reading. None was run. Unchanged since the audit: SA-93, SA-102, SA-103, SA-104, SA-140, SA-141, SA-143 to SA-145, SA-147 to SA-149, SA-74, SA-27. Changed, but not at the mechanism: SA-63 (the release rule still admits any `H(pk ‖ AttA)`), SA-69 (`eligible_at` has no production caller), SA-75 (`memoised_lineage` still loads every envelope since R_0), SA-76, SA-71 (only SA-72's change), SA-78, SA-79 (offers are looked up, never consumed), SA-128 (`connect_app_requests` checks only that the session exists), SA-133 (the debit is matched to `consumer_devid` only), SA-80 (comment only). 12g: `sofi/facts.rs:731` still forces `parent_consumed_elsewhere` false at attempt 0. |
| Open PRs that touch these rows | `gh pr list` | #1148 adds counterfeit-acceptance tests for `full_step`, the debit delta, `check_transfer_policy` and the parent link. It does not cover the 11 checks §6.90 lists as untested. #1149 (Lean) and #1147 (spike) touch no row. |

**Open rows by kind** (SA-149 is dBTC's and is left alone):

- **Approved, not done (this plan builds them):** SA-69, SA-75, SA-76, SA-71, SA-103, SA-104, SA-144, SA-145, SA-147. Also two that may already be closed and need a test to decide: SA-94 (#1146 now records the frontier the accept validated) and SA-92 (A19 replaced A14's held verdict).
- **Approved, the shape is a choice (questions Q1 to Q6 first):** SA-63 with SA-40, SA-78, SA-79, SA-128, SA-148, SA-93.
- **Closable by record, no code:** SA-141 and SA-143. Client DB schema 32 refuses a schema-31 database at open (`enforce_schema_version`), so the rows an earlier build left cannot load. Every schema-32 database was created by a build that writes A18 entries.
- **Owner design, not in this plan until ruled:** SA-03, SA-77, SA-80, SA-102, SA-117 (refusing a tombstoned device's messages), SA-133, SA-140, 12g.
- **Owner-phased or out of scope this round:** offline bearer (SA-10, SA-15, SA-61, SA-91, SA-112, SA-116; the owner's phases 2 to 4), hardware (SA-05, SA-06, SA-26, SA-27, SA-28, SA-57, SA-74, §6.36 part I), BLE (SA-35, SA-51's remaining part), SA-50's remaining part, SA-58's remaining part (spec §14.4), SA-25's remaining part.
- **Verification gaps:** the 11 credit-source checks in §6.90 with no named test that fails when the check is removed.

## 2 Questions for the owner (blocking Tasks 8 and 9)

- **Q1 (SA-63, SA-40).** Any key can sign a faucet release for a device id it makes up, and every future reserve cell can be computed today, because a reserve root depends only on its generation. Should a reserve root commit the previous release's step digest, so a cell's key exists only after its predecessor is won? That restarts the ERA reserve lineage, which needs a node wipe.
- **Q2 (SA-63).** What makes a claimant entitled to a release? A genesis can be made by anyone, so a registered genesis does not stop a throwaway identity. Should the release carry the claimant's directory entry, so its bytes decide entitlement? Or should entitlement be left alone, with Q1's predecessor binding only stopping cells being taken in advance?
- **Q3 (SA-79).** Should a Connect offer be single-use, or good for a fixed number of accepts? An expiry by time is out, because DSM validity reads no clock.
- **Q4 (SA-78).** For requests a grant allows without spending: should there be a per-session count over the session's life, or should those answers stop being kept in `connect_log`, or both?
- **Q5 (SA-128).** Should the wallet authenticate its read of a session's requests with a read secret? The wallet would commit `H(secret)` in its signed accept and present the secret on each read. The alternative is signing each read with the session key, which costs a SPHINCS+ signature per poll. Either way it is a wire change between the app host and the wallet.
- **Q6 (SA-148).** `token.forget` leaves the adoption leaf, the balance row and the cached policy, so the issuer can keep crediting. Should forget refuse while the balance is not zero? Or should it be a device-state transition that removes the adoption leaf, after which credits in that token are refused?
- **Q7 (SA-93).** The identity being verified chooses how far back its EK ancestry walk goes, up to 4096 fetches. Should that walk start from the EK this device recorded with its A19 frontier for that identity, so only new rotations are walked? Past the 512-position budget the result would be Incomplete.

## Global Constraints

- No placeholders, no fabricated values, no refusal standing in for unbuilt work (CLAUDE.md). New lines must pass `scripts/real_code_guard.py`. In tests, use `assert!`/`matches!` rather than the boolean literals, and never `unwrap_or_default`, `let _ =` or `.ok();`.
- Token identity is the policy commitment; the ticker is for display only.
- No JSON or hex in DSM protocol paths; BLAKE3 domain-separated; SPHINCS+ for DSM signatures; no wall-clock in validity or ordering (`ci/no_clock_and_no_json.sh` scans `#[cfg(test)]` too).
- No migrations in beta. A schema bump refuses the old database at open and never silently destroys economic state, offline bearer state, recovery material or pending transfer evidence (owner, 2026-10-18).
- dBTC/Bitcoin code is not touched. `canonicalize_token_id`'s dBTC alias arm and `token_decimals`' BTC line stay byte for byte.
- Storage nodes stay byte stores; nothing a node returns is a verdict; absence is never a verdict.
- A new wire field owes the vector corpus in every copy.
- Each fix: a test that performs the attack, red before the fix; one `DSM_MUTANT` build with the mutants in their own worktree and target dir; targeted release runs; `make lint` at the repo root; regenerate `scripts/sphincs_source_map.py` before every push.
- Commits are attributed to the owner only: no Co-Authored-By trailer.
- End-to-end node tests run on Postgres (`DSM_TEST_DATABASE_URL`), never SQLite.

## Review Focus

1. **A flood placed before the honest object.** Every bound in Tasks 2, 3 and 9 must hold when the junk is written first, not only after. Each task's test writes the junk first.
2. **A reset that drops evidence.** Task 5's schema bump must refuse at open and leave the file byte-identical. The test compares file digests before and after.
3. **A device that crashes between sign and install.** Task 4's test kills the process at that point (a fresh process that keeps nothing it read), not in-process.
4. **Look-alike tickers.** Task 5 covers "era", "ERA " (padded), a control character and a non-ASCII ticker, each held next to real ERA.
5. **Amounts at the top of the range.** Task 5's history test receives `2^63` and `u64::MAX` base units.

---

## 3 Tasks

### Task 1: Coverage regression on `main` (real relay test)

**Files:** `crates/dsm-app-host/tests/real_connection.rs` (the failing step: `answered`, line 667, under `until`, line 467); the cause is likely in what #1142 changed in `dsm_sdk/src/sdk/connect/wallet.rs` (SA-82 `MIN_CYCLE`, `pause_after`) or `dsm_sdk/src/handlers/connect_routes.rs` (SA-127 `session_lock`, `Flow::Waiting`; SA-81 accept short-cut).

- [ ] Reproduce under the Coverage job's profile with the same command as `.github/workflows/` Coverage runs, filtered to `real_connection`. Record the time each step takes.
- [ ] Run the same profile at `7e23a388` (green) and compare per-step times. Bisect #1142's changes to the Connect files.
- [ ] Decide from the measurement. If request 1 is answered and the debug build is merely slower, the fix is whatever made that step cost more, not a larger `STEP`. If request 1 is never answered, it is a real stall in debug, and the fix is the code.
- [ ] Release `real_connection` passes, and the Coverage-profile run passes. Commit `fix(connect): <cause>`.

### Task 2: SA-69, checkpoints become candidates only when eligible

**Files:** modify `dsm_sdk/src/sdk/lineage_discovery.rs` (`Candidates::add`, lines 73 to 91; `discover`, line 173), `dsm_sdk/src/sdk/native_reserve.rs` (`read_named`, `walk_reserve`). Test in `dsm_sdk/src/sdk/lineage_discovery.rs` tests and `dsm_sdk/src/handlers/faucet_flow_tests.rs`.

**Interfaces:**
- Consumes: `dsm::shared_lineage::CheckpointV1::eligible_at(&self, &EstablishedSharedHead) -> Result<(), CheckpointIneligible>` (`dsm/src/shared_lineage/mod.rs:713`).
- Produces: `Candidates::add` keeps a decoded checkpoint aside and inserts no root from it. `Candidates::admit_checkpoints(&mut self, head: &EstablishedSharedHead)` inserts the roots of the checkpoints eligible at `head`. `walk_reserve` calls it at each head it establishes. Discovery still constructs no established state (`discovery_code_names_no_constructor_of_established_state` stays green).

- [ ] Test `a_checkpoint_not_eligible_at_the_established_head_names_no_candidate`: a checkpoint for another lineage, another start, a wrong start digest and a wrong start root each leave `roots_at(g)` without its roots. An eligible one adds them.
- [ ] Test `handlers::faucet_flow_tests::checkpoints_nobody_established_cost_a_claim_no_reads`: unsigned checkpoints naming made-up roots are published at the epoch locator first. The claim succeeds, and the read counter (as in `a_faucet_claim_reads_the_cell_it_won_once`) shows no cell read for a made-up root.
- [ ] Run both, confirm red; implement; run green.
- [ ] Mutation: `admit_checkpoints` ignores `eligible_at`. Both tests red.
- [ ] Commit `fix(faucet): a checkpoint names candidates only once eligible at an established head (SA-69)`.

### Task 3: SA-75 and SA-76, the reserve walk holds bounded memory

**Files:** `dsm_sdk/src/storage/client_db/native_reserve.rs` (`memoised_lineage`, line 134; `record_final_release`, line 79), `dsm_sdk/src/sdk/native_reserve.rs` (`established_chain`, `owe_after_walk`, `ReadAhead`, `CELLS_AT_ONCE`).

**Interfaces:**
- Produces: `memo::established_steps(genesis, from_generation: u64) -> Result<Vec<(u64, [u8; 32], [u8; 32])>>`, giving the generation, root and step digest with no envelope. The step digest is stored at `record_final_release`, in a new column added under the branch's single bump to schema 33 (made by whichever of this task and Task 5 lands first). `established_chain` reads only from the first epoch that still owes a hint or a checkpoint. `ReadAhead` holds at most `READ_AHEAD_BYTES` (proposed 8 MiB) of kept release bytes. A cell past the total is read when the walk reaches it.

- [ ] Test `a_reserve_walk_reads_no_envelope_it_already_settled`: a memo of N generations. A walk from the latest state loads no envelope below the first owed epoch (counted at the memo).
- [ ] Test `a_read_ahead_window_holds_no_more_than_its_byte_total`: cells each holding many distinct recognized releases (throwaway-signed, written first). The window's kept bytes never exceed `READ_AHEAD_BYTES`, and the walk still reaches the head.
- [ ] Red, implement, green.
- [ ] Mutations: `established_chain` back on `memoised_lineage`; the byte total unchecked. Each red.
- [ ] Commit `fix(faucet): the reserve walk reads only the epochs it owes and holds its window to a byte total (SA-75, SA-76)`.

### Task 4: SA-71, a device follows its own fulfillment that holds the key (§25)

**Files:** `dsm_sdk/src/sdk/sofi_advance.rs` (`resolve_pending_position`, line 708), `dsm_sdk/src/sdk/sofi_register.rs` (`install_fulfillment`, line 167), `dsm_sdk/src/sdk/sofi_flow.rs` (`exercise_draft_at_head`, line 1992). Test in `dsm_sdk/src/handlers/node_e2e_tests.rs`.

**Interfaces:** `resolve_pending_position` gets a case for "the leader of `K_ful(q)` holds another fulfillment this device signed". Resolution follows that fulfillment's outcome; it does not refuse the position for good. `install_fulfillment` reads `K_ful(q)` before writing. §25 is unchanged: an F signed and never published may still be discarded.

- [ ] Read both functions in full first. If the refusal is not where the audit placed it (`sofi_flow.rs:1989` at `7e23a388`), re-locate it before writing the test.
- [ ] Test `a_fulfillment_of_mine_replayed_into_its_key_is_followed_not_refused`: trader B signs and publishes F1 at q. The process ends before install, and a fresh process signs F2 at q. F1 is written to `K_ful(q)`'s leader first. B's position resolves under F1, and B can trade again.
- [ ] Red, implement, green.
- [ ] Mutation: the new case removed. Red.
- [ ] Commit `fix(sofi): a device follows its own fulfillment that holds the key (SA-71, SoFi §25)`.

### Task 5: Token-row schema cut (SA-103, SA-104, SA-144, SA-145, SA-147)

**Files:** `dsm_sdk/src/storage/client_db/mod.rs` (`CLIENT_DB_SCHEMA_VERSION` 32 → 33; `contacts` table, line 915), `dsm_sdk/src/storage/client_db/tokens.rs` (`validate_projection_identity`, line 20; `upsert_balance_projection_with_conn`, line 52), `dsm_sdk/src/handlers/wallet_routes.rs` (`canonicalize_token_id`, line 441; `merge_balance_projections`, line 415; `event_transaction`, line 70), `dsm_sdk/src/sdk/contact_sdk.rs` (line 104, `contact_id`), `proto/` (the history amount), the vector corpus.

**Interfaces:**
- Balance projections are keyed `(device_id, policy_commit)`, and the first-writer ticker lock is gone (SA-104).
- Builtin tickers match exactly, with no case folding. The dBTC arm is unchanged (SA-145).
- `balance.list` never fails on a ticker: rows are keyed by commit, and the ticker is rendered at the display edge (SA-103).
- The history amount is a `u64` with a direction field, never `-(amount as i64)` (SA-144; wire change; frontend reads the new field).
- The contact key is the full device id (SA-147).

- [ ] Tests, each red first:
  - `a_coin_named_era_never_takes_the_era_row`
  - `a_lookalike_era_ticker_never_displays_or_credits_as_era`, covering "era", "ERA " and a control character
  - `a_ticker_that_cannot_be_displayed_breaks_no_balance_list`
  - `history_carries_received_amounts_at_the_top_of_the_range`, with `2^63` and `u64::MAX`
  - `two_device_ids_sharing_a_prefix_hold_two_contacts`
  - `a_schema_32_database_is_refused_at_open_and_left_byte_identical`
  - `a_reprovisioned_wallet_reads_its_balances_back_from_the_network`
- [ ] Implement. Regenerate the vector corpus copies for the new history field.
- [ ] Green, release, the filtered `wallet_routes`, `tokens`, `contact_sdk` and `client_db` modules.
- [ ] Mutations: case folding restored; the ticker key restored; the i64 negation restored; the truncated contact key restored. Each red.
- [ ] Commit `fix(tokens): balance rows, contacts and history keyed by what they are, schema 33 (SA-103, 104, 144, 145, 147)`.

### Task 6: Tests for the 11 untested credit-source checks (§6.90)

Starts after #1148 merges, to reuse its harness (`dsm_sdk::handlers::counterfeit_acceptance_tests`).

**Checks:** `asset_eq`, `dup_source`, `consumed_from_zero`, `consumer_op_id`, `debit_addressed_to_consumer`, `debit_is_op_debit`, `witness_matches_validated_root`, `acceptance_bundle_addr`, `acceptance_verified`, `reserve_coordinates` (R02's wrong-generation case), `source_may_name_sources`.

- [ ] One test per check that builds the inconsistent evidence with the producer's own builders and asserts a receiver new to the payer refuses it, through the production resolver and `prevalidate_incoming_transfer_admission`.
- [ ] One `DSM_MUTANT` build that skips each check in turn, with a clean control. Each mutant turns its named test red. A mutant that stays green is recorded as a finding about the check, not as a pass.
- [ ] Record in §6.90 and VERIFICATION_MATRIX. Commit `test(economic): every credit-source check has a test that performs what it refuses`.

### Task 7: SA-94 and SA-92 under A19, test first

- [ ] SA-94: test `a_sender_that_moves_after_the_accept_cannot_fence_the_recipient`. After the recipient's accept and register, the sender writes a conflicting claim at its paying position; the recipient's finish (`economic_admission_flow.rs` `finish_locked`, line 1017) completes. If the test is green on `main`, #1146's frontier closed it: record SA-94 Fixed with the test and a mutation (no frontier recorded at the accept turns it red). If it is red, fix it under the owner's condition, "a frozen witness must prove an accepted sender state", and ask before choosing the mechanism.
- [ ] SA-92: test that a persisted vault-chain row cannot answer a position Core now rules Invalid. Same outcome rule.
- [ ] Commit per outcome.

### Task 8: Faucet entitlement and predecessor binding (SA-63, SA-40). Blocked on Q1, Q2.

The owner ruled that the faucet changes land together: entitlement, predecessor binding, candidate recognition (Task 2) and bounded walks (Task 3). The design follows the answers. Files: `dsm/src/economic/native_reserve.rs` (`NativeReserveState::root`, line 168; `release_constructible`, line 480). The test performs the throwaway-key occupation of future cells and asserts a claim still wins.

### Task 9: Connect bounds and authenticated reads (SA-78, SA-79, SA-128). Blocked on Q3 to Q5.

Files: `dsm_sdk/src/handlers/connect_routes.rs` (`connect_app_accept`, line 1729; `connect_app_requests`, line 2790), `dsm_sdk/src/sdk/connect/grant.rs` (`decide`), `dsm_sdk/src/storage/client_db/connect.rs` (`app_offer`, line 731). SA-128 is a proto and connect-schema change, and owes the vector corpus. Tests perform each attack: an offer accepted again past its use count, a flood of zero-spend requests, and a read of another session's requests.

### Task 10: Records

- [ ] CONFORMANCE_GAPS: move each row this plan closes. Close SA-141 and SA-143 by record, citing schema 32's refusal at open and the test that shows it. Replace the six deleted test names in §6.86 and the SA-92 entry with what replaced them. Add a §6.9x entry for this round with the suites and mutations.
- [ ] VERIFICATION_MATRIX: one row per mutation.
- [ ] Run `ci/conformance_evidence.py` and the real-code guard against `origin/main`. Then the board, as CI runs it, from `dsm_client/deterministic_state_machine/`: `cargo test --locked --workspace --exclude dsm_storage_node --release -- --nocapture --test-threads=1`, plus `cargo test -p dsm_storage_node` on Postgres and `make lint`. Name crates and counts.
- [ ] `git fetch`, rebase on `origin/main`, then `git push origin HEAD:refs/heads/fix/security-audit-open-rows` and open one PR.
