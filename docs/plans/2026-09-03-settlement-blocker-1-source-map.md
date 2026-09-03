# Settlement blocker 1 read-only source map

Status: source-map only. Branch `feat/settlement-blocker-1-source-map`
starts from merged `origin/main` `dbd1a56e` (#760), with the local #760
accuracy cleanup carried forward because merged main does not contain it.

This file does not implement settlement. It deliberately leaves DLV derivation,
CCB, create gates, rehydration gates, publish gates, frontend behavior and the
wipe boundary unchanged.

## Closure finding

The pieces needed for admitted settlement exist, but the chain is not closed
end-to-end for `DlvSettle` and `DlvOwnerApplyV2`.

- `dlv.unlockRouted` builds and signs `Operation::DlvSettle`, then calls the
  plain relationship executor: `dsm_sdk/src/handlers/dlv_routes.rs:2980-3048`.
  No `AdmissionPlan` is attached on this path.
- `dlv.reconcile` builds and signs `Operation::DlvOwnerApplyV2`, then calls the
  reserve-mutating relationship executor:
  `dsm_sdk/src/handlers/dlv_routes.rs:1680-1829`. No `AdmissionPlan` is
  attached on this path.
- The executor admits economic state only when a caller passes an
  `AdmissionPlan`: `dsm_sdk/src/sdk/core_sdk.rs:1905-2046`.
- The current shared admission builder stages `EconomicPreState::balances_only`:
  `dsm_sdk/src/sdk/economic_admission_flow.rs:243-251`. `DlvOwnerApplyV2`
  write-set construction needs predecessor reserve leaves through
  `EconomicPreState.vault_reserves`: `dsm/src/economic/write_set.rs:220-238`
  and `dsm/src/economic/write_set.rs:792-867`.

So the next settlement work is not free to write runtime logic yet. It first
has to close the admission/evidence chain for trader settlement and owner
application against one authenticated `R_econ` predecessor.

## Required anchors

| Anchor | Current source | Settlement implication |
|---|---|---|
| Exact owner-fold entry | `dlv.reconcile` is the owner fold: `dsm_sdk/src/handlers/dlv_routes.rs:1565-1576`. It fetches a verified receipt at `1592-1602`, derives the consumed parent binding at `1644-1679`, builds `DlvOwnerApplyV2` at `1680-1707`, signs it at `1709-1718`, builds `VaultReserveMutation::ApplySettlement` at `1760-1769`, and advances at `1821-1829`. | This is the route entry to wire into admitted owner apply. The request only names `(vault_id, x)`; the signed operation and reserve mutation are derived locally from receipt and owner record. |
| Authoritative predecessor-reserve source | The read-time market source is composition: `compose_discovered_vault` resolves advertisement -> presentation -> `CCB(V_n)` -> fold at `dsm_sdk/src/sdk/vault_state_composition.rs:571-633`; `compose_vault_state` verifies baseline, storage set, quorum and register-cell walk at `222-349`, validates settlement/close edges at `360-479`, re-simulates and folds reserves at `508-568`. Owner-local composition uses the same path through `compose_own_vault`: `dsm_sdk/src/handlers/dlv_routes.rs:3480-3552`. Economic pre-state support exists in `EconomicPreState.vault_reserves`: `dsm/src/economic/write_set.rs:220-238`. | The settlement branch must decide how the owner-side admitted predecessor reserve leaves are decoded from the admitted economic root and supplied to `build_write_set`. Using device-head leaves alone would not establish the economic predecessor. |
| Existing AMM curve verifier | Route unlock verifier: `dsm_sdk/src/sdk/route_commit_sdk.rs:754-842`. Composition replays the same curve against each cursor: `dsm_sdk/src/sdk/vault_state_composition.rs:508-518`. Economic provenance re-simulates the settled route at `dsm/src/economic/provenance.rs:1131-1170`. | The curve math is already centralized enough for settlement; the missing work is passing the verified reserve/evidence facts through admission, not replacing AMM math. |
| DLV policy evaluation point | DLV policy members live in `VaultStateV2.release_policy` and `VaultStateV2.fee_policy`: `dsm/src/ccb/state.rs:267-289`, encoded at `313-315`. The AMM DLV-policy digest is the derived view of those members: `dsm/src/ccb/mod.rs:509-530`. The beta release family is `ReleasePolicy::beta_owner_local_full_close`: `dsm/src/ccb/state.rs:213-223`; close execution is enforced by the `DlvClose` withdraw arm: `dsm/src/types/device_state.rs:2260-2390`. Fee policy is consumed by route, composition and provenance AMM checks. | Treat DLV policy evaluation as the current release/fee-family checks. Do not introduce a second policy identity; non-AMM DLVs still carry caller-supplied but creator-signed 32-byte policy bytes until their semantic authority is designed. |
| CPTA policy evaluation for both assets | Route pre-flight fetches/roots policy bytes and calls `check_market_leg_permitted`: `dsm_sdk/src/handlers/dlv_routes.rs:41-95`. It is called for owner apply at `1752-1758`, close at `2443-2450`, and trader settle at `2915-2924`. The advance funnel enforces the same local gate at `dsm_sdk/src/sdk/core_sdk.rs:1331-1372` and calls it at `1888-1903`. The foreign-verifiable economic conjunct extracts both legs at `dsm/src/economic/provenance.rs:1462-1487` and verifies policy bytes at `1489-1517`; `advance_validated` runs it at `dsm/src/economic/lineage.rs:582-590`. | Both assets already have three layers of policy checks. Settlement wiring must preserve all three: route fetch/root, local advance, and economic verification. |
| Exact `R_econ` write-set builder | Operation classification marks `DlvSettle` and `DlvOwnerApplyV2` as closed write sets: `dsm/src/economic/classifier.rs:71-83`. The semantic table defines the DLV shapes at `dsm/src/economic/write_set.rs:267-323` and maps operations at `492-580`. `build_write_set` starts at `611-619`; DlvSettle production is `740-791`; DlvOwnerApply production is `792-867`. The verifier checks exact DlvSettle shape at `1420-1491` and exact DlvOwnerApply shape at `1493-1586`. | This is the only write-set source settlement should use. Do not duplicate R_econ mutation logic in route code. |
| Admission executor | Staging resolves predecessor, tree and authority at `dsm_sdk/src/sdk/economic_admission_flow.rs:416-465`. Plain admitted self-loop facade is `484-565`; funded DLV create facade is `591-727`; `finish_admission` publishes evidence, registers the root and calls the verifier at `731-924`. The verifier is `advance_validated`: `dsm/src/economic/lineage.rs:435-600`. | Settlement needs its own narrow admitted facades or a generalized facade that can carry `DlvReserveConsumption` and `DlvSettlementPayment` facts plus reserve pre-state. Existing plain executor calls are not enough. |
| Irreversible owner signing/fold point | Owner apply signs before the fold at `dsm_sdk/src/handlers/dlv_routes.rs:1709-1718`, then commits through the reserve-mutating executor at `1821-1829`. Close signs and claims before the canonical close at `2452-2468` and `2555-2611`; `commit_canonical_close` commits release, consume-once claim and terminal artifacts at `1841-1990`. Core verifies DLV signatures before deriving the tip at `dsm/src/types/device_state.rs:1655-1689`, advances owner-apply reserves at `2080-2258`, derives vault-state leaves at `2393-2441`, updates all leaves into one root at `2506-2675`, and returns the new device state at `2724-2763`. | The point of no return is the signed operation plus the device-root advance. Settlement admission must be attached before this reports success, with the same operation bytes and root evidence. |

## Evidence anchors already present

- Reserve-consumption evidence shape carries exact `CCB(V_n)`, owner authority
  evidence, and both reserve leaf witnesses:
  `dsm/src/economic/reserve_consumption_evidence.rs:3-30`.
- Settlement-payment evidence shape carries the trader settlement-receipt leaf
  and its witness:
  `dsm/src/economic/settlement_payment_evidence.rs:3-21`.
- Economic provenance validates DLV reserve consumption by verifying `CCB(V_n)`,
  owner authority, owner validated root, reserve leaf inclusion, AMM
  re-simulation and slot winner:
  `dsm/src/economic/provenance.rs:932-1207`.
- Economic provenance validates owner apply payment by verifying the trader
  validated root and receipt leaf inclusion:
  `dsm/src/economic/provenance.rs:1208-1327`.

Those are verifier-side anchors, not route admission wiring. The settlement
implementation is blocked until the route producers build these evidence
objects from the exact admission positions they will occupy and feed them
through the admission executor.
