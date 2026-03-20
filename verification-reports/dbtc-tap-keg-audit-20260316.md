# dBTC Tap/Keg Protocol-Path Compliance Audit

Date: 2026-03-16

Primary baseline:
- `docs/papers/dBTC_implement.pdf`

Supporting reference only:
- `docs/papers/DSM__A_Concise__Post_Quantum_Specification.pdf`

## Scope

This audit reviewed the protocol path only:

- core tap/vault logic
- Bitcoin bridge SDK
- withdrawal execution and settlement handlers
- storage-backed vault discovery
- withdrawal persistence and refund mechanics

Frontend/UI behavior was excluded unless it affected protocol security or correctness.

## Verdict

The implementation matches parts of the dBTC paper well at the deposit-proof boundary, successor guard rails, protobuf/canonical-commit handling, and storage-node non-authority model. The withdrawal path does **not** currently implement the paper's bearer-authorized, amount-exact, commit-then-settle-or-refund model.

The highest-risk problems are:

1. withdrawal value is accounted for multiple times across commit, leg execution, and settlement
2. the settlement monitor can emit compensating dBTC credits for withdrawals that already produced Bitcoin side effects
3. storage-discovered grid redemption is planned as available but is not executable without local creator-side secret state

## Findings

### 1. [Critical] Withdrawal commitment is accounted for multiple times

Paper clauses:
- Definition 10 (In-Flight Commitment)
- Property 4 (Amount-Exact Commitment)
- §13.1 State Machine
- Property 8 (Commit-on-Execution, Finalize-on-Settlement, Refund-on-Failure)
- Property 12 (Mint/Burn Conservation)

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:375-399` commits the withdrawal before any leg executes.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/withdrawals.rs:39-97` moves `available -> locked` for the committed amount.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:1943-1945` and `:2333-2334` lock dBTC again for each fractional/full leg.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:2070-2104` and `:2579-2610` burn/finalize again after the leg broadcast succeeds.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:4021-4041` burns again at settlement.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/withdrawals.rs:122-156` removes the committed locked amount again at settlement.

Why this violates the paper:
- The paper defines a single in-flight commitment that reserves exactly `a`, followed by either settlement or refund.
- The code maintains a second, independent per-leg lock/burn path in parallel with the in-flight withdrawal record.
- If the user has exactly the requested amount, the post-commit leg lock can fail because the first commit already consumed the available balance.
- If the user has more than the requested amount, the code can reserve and burn more state than the original commitment accounts for.

Impact:
- execution can fail spuriously on valid withdrawals
- settlement semantics are no longer amount-exact
- conservation reasoning in §19 is broken by implementation, even if the paper's model is sound

Recommended remediation:
- Make the in-flight withdrawal record the only token-accounting authority for execution and settlement.
- Remove the second SQLite `lock_dbtc_for_exit` / `finalize_exit_burn` path from withdrawal legs, or formally rebase the legs to consume the committed locked amount instead of re-locking from spendable balance.
- Add an end-to-end test that executes a real plan with exact-balance funding and asserts: `available -> locked -> settled/refunded` exactly once.

### 2. [Critical] Settlement monitor can emit compensating dBTC credits for withdrawals that already broadcast or partially executed

Paper clauses:
- §13.1 State Machine
- §14 Full Withdrawal steps 5-7
- Definition 15 (Automatic Refund)
- Property 9 (No Stranded Value)

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:448-485` marks partial failures but does not persist any already-broadcast txids.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:514-528` records redemption txids only after all legs succeed, and txid persistence failure is logged but not fatal.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:3833-3905` auto-refunds any unresolved withdrawal older than 3600 ticks when `redemption_txid` is empty.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:3936-3993` treats any `tx_status` lookup failure, including API error, as a refund condition.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:3843-3848` and `:3951-3956` create forward `TokenOperation::Unlock` credits on the local hash chain.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:4293-4310` builds an additional self-transfer refund message for inbox delivery.

Why this violates the paper:
- The paper's refund condition is `FailBeforeSettlement(ρ)`, not "local metadata missing" and not "external status API errored."
- A crash after broadcast but before txid persistence, or a partial route where one leg already succeeded, can satisfy the code's stale/no-txid refund branch even though Bitcoin side effects already occurred.
- A transient mempool/API failure can trigger the refund branch even when the Bitcoin transaction is still valid.
- DSM is forward-only, so nothing here rolls back prior state. The issue is that the code can mint economic relief by appending new unlock/credit states after Bitcoin value may already have been delivered.

Impact:
- double-credit risk: the user can receive Bitcoin and later receive an additional forward dBTC credit/unlock
- partial routes can credit the full committed amount without netting out already-broadcast legs
- compensating-credit correctness depends on local bookkeeping durability and third-party API availability, which the paper explicitly tries to avoid

Recommended remediation:
- Persist txids atomically with each successful leg, before returning from the leg loop.
- Distinguish "unknown status" from "failed redemption"; do not emit unlock/credit recovery on API/network errors alone.
- Replace the fixed no-txid stale refund heuristic with crash-recovery state that proves no broadcast occurred.
- Add a test that simulates: leg broadcast succeeds, txid persistence fails, settlement monitor runs, and no compensating credit is emitted.

### 3. [High] Grid-based bearer redemption is planned as available but is not executable without local creator-side state

Paper clauses:
- Property 5 (No Middleman Authorization)
- Invariant 6 (Transfer Purity)
- Definition 13 (Policy-Compatible Vault Set)
- Property 7 (Redemption Is Grid-Based)
- §21.2 Transfer and §21.3 Withdrawal

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:2863-2876` explicitly treats storage-discovered vaults with no local vault record as routeable.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:3419-3436` adds remote advertisements to the eligible withdrawal set after loading only public vault artifacts.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:2233-2252` requires a local `VaultOperation` record for execution.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1528` and `:1794` make `pour_partial()` and `drain_tap()` depend on that local vault record.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:2347-2385` requires locally persisted `htlc_script`, `htlc_address`, and `preimage` before a full sweep can proceed.

Why this violates the paper:
- The paper says the bearer may redeem against any compatible live vault in the grid and does not depend on the original depositor.
- In code, planning accepts remote vaults as usable, but execution falls back to creator-local vault records and locally persisted secret material.
- A recipient who only received fungible dBTC does not receive the secret state required by the current execution path.

Impact:
- storage-discovered liquidity is overstated at planning time
- redemption remains effectively tied to devices that already hold creator-side vault records
- the claimed fungible "any vault in the grid" model is not implemented

Recommended remediation:
- Either implement the paper's bearer-derived witness derivation so remote vaults are truly executable from public ad data plus bearer-side secret state, or stop advertising remote vaults as executable in the planner.
- Add an end-to-end test where device B receives dBTC from device A and redeems against a vault created by A without importing A's vault record database.

### 4. [High] Bearer witness material is persisted at rest on the creator device

Paper clauses:
- §10.1 The Redemption Witness Boundary
- Definition 11 (Redemption Witness Decomposition)
- Invariant 5 (Bearer Witness Is Never at Rest)
- Property 6 (No Secret in the Advertisement)

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1362-1370` generates the vault preimage.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1430-1436` persists that preimage in the vault operation record.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1595-1608` derives successor preimages.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1678-1684` persists successor preimages too.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/vault_records.rs:13-19` and `:57-70` store `preimage` in SQLite.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/storage/client_db/vault_records.rs:325-352` exposes `(vault_id, preimage, entry_txid)` to higher layers.

Why this violates the paper:
- The paper states the bearer-derived witness has no representation "not on the creator's device, not on the storage nodes, not in any prior transaction" before redemption time.
- The implementation keeps the preimage as durable local state and reuses it later to construct the Bitcoin spend.

Impact:
- local SQLite compromise exposes sweep authority for mirrored vaults
- the implementation contradicts one of the paper's central trust-boundary claims
- the current redemption model depends on secret retention rather than on paper-style bearer-side derivation

Recommended remediation:
- Stop persisting redeeming preimages in SQLite.
- If the protocol really requires persistent secret material, revise the threat model and paper claims to match reality.
- Add a storage audit test that verifies vault advertisements remain secret-free while local persistence also excludes preimage/bearer witness material.

### 5. [Medium, intentional deviation] Non-mainnet paths relax the paper's burial and anchoring requirements

Paper clauses:
- Definition 13 and §17 (the canonical `dmin = 100` gate)
- §21.1 Deposit step 2
- §21.3 Withdrawal step 5

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:204-221` resolves non-mainnet confirmation depth to `1` unless overridden.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1384-1389` sets Signet/Testnet deposit minimum confirmations to `1`.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1628-1632` sets successor minimum confirmations to `1`.
- `dsm_client/deterministic_state_machine/dsm/src/bitcoin/header_chain.rs:121-129` bypasses checkpoint-rooted header-chain enforcement on Signet/Testnet.
- `dsm_client/deterministic_state_machine/dsm/src/bitcoin/header_chain.rs:209-211` bypasses entry-anchor chain verification on Signet/Testnet.

Assessment:
- This is consistent with a test/dev shortcut, not a mainnet-only defect.
- It is still a strict-baseline deviation from the paper and weakens the value of non-mainnet tests as compliance evidence.

Recommended remediation:
- Keep the shortcut if needed for development, but label it explicitly as non-paper mode and gate it behind an unmistakable runtime flag.
- Add at least one mainnet-style integration mode or deterministic unit harness that exercises the full `dmin=100` and checkpoint path.

### 6. [Low, intentional deviation] `open_tap()` publishes vault advertisements before the paper's deposit lifecycle is complete

Paper clauses:
- Definition 9 (Vault Advertisement includes `entry_txid`)
- §21.1 Deposit steps 2-4

Code evidence:
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:683-696` persists and immediately publishes the vault advertisement during `open_tap()`.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:1282-1300` later stores `entry_txid` and republishes after activation, with a comment acknowledging the early-publication behavior.

Assessment:
- The later republish mitigates discoverability drift.
- The initial publication still exposes pre-activation taps to storage nodes before the paper's "funded to `dmin`, minted, then published" lifecycle completes.

Recommended remediation:
- Publish only after activation/entry anchoring, or use a clearly separate pending-advertisement namespace that cannot be mistaken for live grid liquidity.

## Traceability Matrix

| Claim group | dBTC clause | Expected behavior | Primary code locus | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| Collateral grid by shared policy | Definition 13, Property 7 | withdrawal planner treats compatible vaults as one liquidity grid | `bitcoin_tap_sdk.rs:3300-3436` | `sdk-only` | Implemented in SDK planning, not protocol core |
| Deposit proof and burial gate before mint | §21.1, §17 | mint only after valid SPV proof and sufficient confirmations | `bitcoin_tap_sdk.rs:1930-2046`, `limbo_vault.rs:1376-1512` | `enforced` | Core HTLC verifier derives depth from header chain and checks SPV/anchors |
| Vault advertisement contains public construction data only | Definition 9, Property 6 | storage ads carry public routing/construction data, not secrets | `bitcoin_tap_sdk.rs:2943-2964` | `enforced` | Advertisement payload is public-only; this does not fix local secret persistence |
| Storage nodes are discovery, not authority | Invariant 4, Property 11, Invariant 12 | storage nodes help discover; Bitcoin and DSM decide liveness/accounting | `bitcoin_tap_sdk.rs:3321-3374`, `header_chain.rs`, `operations.rs:7-10` | `enforced` | Also consistent with DSM concise spec non-authoritative storage guidance |
| Transfer purity / no vault baggage in token transfer | Definition 12, Invariant 6 | token transfer changes balances only | `operations.rs:177-201`, `token_sdk.rs:880-909` | `enforced` | Transfer op carries token/balance metadata only |
| Depositor independence / bearer can redeem any live compatible vault | Property 5, §21.2-§21.3 | recipient redeems against grid without creator cooperation | `bitcoin_tap_sdk.rs:2863-2876`, `:3419-3436`, `:2233-2252`; `bitcoin_invoke_routes.rs:2347-2385` | `missing` | Planner says yes; execution still requires creator-local record/preimage |
| Bearer witness never at rest | Invariant 5 | no durable preimage/witness storage before spend time | `bitcoin_tap_sdk.rs:1430-1436`, `:1678-1684`; `vault_records.rs:57-70` | `missing` | Local SQLite persistence directly contradicts paper text |
| Commit-then-settle-or-refund state machine | §13, Property 8 | one commitment path, then settle or refund automatically | `withdrawals.rs`, `bitcoin_invoke_routes.rs:375-405`, `:1939-2104`, `:2333-2610`, `:4010-4043` | `missing` | Current implementation mixes in-flight accounting with separate per-leg accounting |
| Amount-exact commitment | Property 4 | committed amount authorizes exactly that amount | same as above | `missing` | Double lock/burn path breaks exactness |
| Offline-tolerant automatic refund | Definition 15, Invariant 9 | compensating unlock/credit only on actual failure-before-settlement | `bitcoin_invoke_routes.rs:3833-3905`, `:3936-3993`, `:4293-4310` | `missing` | Missing txid metadata or API failure can currently trigger an unsafe forward credit |
| Fractional exit bounds | Definition 16, §17 | partial exit enforces positive amount, min remainder, bounded successor depth | `bitcoin_tap_sdk.rs:1512-1593` | `enforced` | Guard rails match paper intent |
| Successors stay in the grid | Invariant 10 | successor remains under same policy and is later re-advertised | `bitcoin_tap_sdk.rs:1634-1659`, `:1743-1748` | `sdk-only` | Successor creation/publish sequencing exists in SDK; not covered by passing E2E evidence here |
| Confirmation-depth and entry-anchor checks on non-mainnet | §17 | same canonical gate across environments | `bitcoin_tap_sdk.rs:204-221`, `:1384-1389`, `:1628-1632`; `header_chain.rs:121-129`, `:209-211` | `intentional deviation` | Test/dev shortcut, not paper-faithful |
| Deposit publication timing | §21.1, Definition 9 | publish after funding reaches `dmin` and `entry_txid` exists | `bitcoin_tap_sdk.rs:683-696`; `bitcoin_invoke_routes.rs:1282-1300` | `intentional deviation` | Early publication later corrected by republish |

## Supporting DSM-spec References

The DSM concise specification was used only as a supporting reference for shared primitives, not as the primary tap/keg baseline. Two points were materially relevant:

- canonical protobuf / canonical-commit authority belongs in core, not in bindings
- storage nodes are non-authoritative mirrors and proof-serving infrastructure

Observed alignment:

- `dsm_client/deterministic_state_machine/dsm/src/types/operations.rs:7-10` keeps authoritative operation encoding on the canonical binary path
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/bitcoin_tap_sdk.rs:1112-1122` verifies remote vault protobuf digest before use

## Verification Notes

Executed tests:

- `cargo test --package dsm_sdk --test withdrawal_refund_inbox_e2e -- --nocapture`
  - result: PASS (`3/3`)
  - what it proves: local compensating-credit bookkeeping, nonce spending, and inbox-refund mechanics at the SQLite/state-machine seam
  - what it does **not** prove: real withdrawal execution, broadcast, settlement, or conservation across the actual sweep path

- `cargo test --package dsm_sdk --test bitcoin_tap_e2e refund_not_available_before_timeout -- --nocapture`
  - result: FAIL in harness
  - failure: `attempt to write a readonly database`
  - location: `dsm_client/deterministic_state_machine/dsm_sdk/tests/bitcoin_tap_e2e.rs:412`
  - implication: tap E2E behavior in this audit is based on code inspection and unit evidence, not a clean passing end-to-end run

Coverage gap that matters for the findings:

- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/bitcoin_invoke_routes.rs:5039-5165` and neighboring withdrawal-execute tests use `set_withdrawal_execution_test_expectations(...)` to stub `invoke_full_sweep_internal` / `invoke_fractional_exit_internal`
- those tests validate plan-cache behavior, not the real balance-locking, burn, txid-persistence, or settlement-monitor paths where the critical findings live

## Residual Risk and Assumptions

- This report assumes the dBTC paper governs when it is more specific than the DSM concise spec.
- Mainnet-only behavior was reviewed by code path; I did not perform live Bitcoin-network execution.
- The tap E2E suite was not cleanly runnable in this environment because of the readonly-SQLite test failure above.
- I did not treat existing comments or traceability docs as proof unless the underlying code enforced the claim.
